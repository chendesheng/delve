package proctl

//#include "mach_darwin.h"
//#include <libproc.h>
//#include <sys/ptrace.h>
import "C"

import (
	"debug/macho"
	"errors"
	"fmt"
	"log"
	"os"
	"reflect"
	"syscall"
	"unsafe"
)

const (
	S_GOSYMTAB    = "__gosymtab"
	S_GOPCLNTAB   = "__gopclntab"
	S_TEXT        = "__text"
	S_DEBUG_FRAME = "__debug_frame"
)

type exefile struct {
	*macho.File
}

type trapEvent struct {
	id     int
	status *syscall.WaitStatus
	err    error
}

type debuggedProcess struct {
	chTrap chan *trapEvent //notify when mach exception happens
}

func (dbp *DebuggedProcess) findExecutable() (exefile, error) {
	procpath := make([]byte, 2048)
	sz := len(procpath)
	sz = int(C.proc_pidpath(C.int(dbp.Pid), unsafe.Pointer(&procpath[0]), C.uint32_t(sz)))
	if sz <= 0 {
		return exefile{}, errors.New("proc_pidpath error")
	}

	f, err := os.OpenFile(string(procpath[:sz]), 0, 0777)
	if err != nil {
		return exefile{}, err
	}

	machofile, err := macho.NewFile(f)
	if err != nil {
		return exefile{}, err
	}

	data, err := machofile.DWARF()
	if err != nil {
		log.Print(err)
		return exefile{}, err
	}
	dbp.Dwarf = data

	return exefile{machofile}, nil
}

func (dbp *DebuggedProcess) addThread(tid int) (*ThreadContext, error) {
	dbp.Threads[tid] = &ThreadContext{
		Id:      tid,
		Process: dbp,
	}

	return dbp.Threads[tid], nil
}

func (dbp *DebuggedProcess) AttachThread(tid int) (*ThreadContext, error) {
	return dbp.addThread(tid)
}

//func addNewThread(dbp *DebuggedProcess, pid int) error {
//	return errors.New("Not implemented")
//}

func stopped(pid int) bool {
	return false
}

func (dbp *DebuggedProcess) RequestManualStop() {
}

func waitroutine(dbp *DebuggedProcess) {
	for {
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(dbp.Pid, &status, 0, nil)
		if status.Exited() {
			dbp.chTrap <- &trapEvent{pid, &status, err}
			return
		}
	}
}

func trapWait(dbp *DebuggedProcess, pid int) (int, *syscall.WaitStatus, error) {
	for {
		evt := <-dbp.chTrap
		wpid, status, err := evt.id, evt.status, evt.err

		if err != nil {
			return -1, nil, fmt.Errorf("wait err %s %d", err, pid)
		}

		if wpid == 0 {
			continue
		}

		if th, ok := dbp.Threads[wpid]; ok {
			th.Status = status
		}

		if status.Exited() && wpid == dbp.Pid {
			dbp.CurrentThread.Status = status
			return -1, status, ProcessExitedError{wpid}
		}

		if status.StopSignal() == syscall.SIGTRAP {
			return wpid, status, nil
		}

		if status.StopSignal() == syscall.SIGSTOP && dbp.halt {
			return -1, nil, ManualStopError{}
		}
	}
}

func wait(pid, options int) (int, *syscall.WaitStatus, error) {
	var status syscall.WaitStatus
	wpid, err := syscall.Wait4(pid, &status, options, nil)
	return wpid, &status, err
}

// Ensure execution of every traced thread is halted.
func stopTheWorld(dbp *DebuggedProcess) error {
	return taskSuspend(dbp.Pid)
}

var fnCatchExceptionRaise func(C.int, C.int, C.exception_type_t, C.exception_data_t, C.mach_msg_type_number_t) int

//export catch_exception_raise
func catch_exception_raise(eport C.int, thread C.int, task C.int, exception C.exception_type_t,
	code C.exception_data_t, ncode C.mach_msg_type_number_t) C.int {

	//log.Print("[exception rise]task:", task, " thread:", thread)
	return C.int(fnCatchExceptionRaise(task, thread, exception, code, ncode))
}

// Returns a new DebuggedProcess struct with sensible defaults.
func newDebugProcess(pid int, attach bool) (*DebuggedProcess, error) {
	dbp := DebuggedProcess{
		Pid:         pid,
		Threads:     make(map[int]*ThreadContext),
		Breakpoints: make(map[uint64]*Breakpoint),
	}
	dbp.chTrap = make(chan *trapEvent)
	for i, _ := range dbp.HWBreakpoints {
		dbp.HWBreakpoints[i] = new(Breakpoint)
	}

	pths := uintptr(0)
	nth := 0
	err := macherr(C.attach(C.int(pid), unsafe.Pointer(&pths), (*C.int)(unsafe.Pointer(&nth))))
	if err != nil {
		return nil, err
	}

	threads := make([]int32, nth)
	head := (*reflect.SliceHeader)(unsafe.Pointer(&threads))
	head.Data = pths
	head.Len = nth
	head.Cap = nth

	if err := taskSuspend(pid); err != nil {
		return nil, err
	}
	log.Printf("threads:%#v", threads)
	for _, t := range threads {
		tid := int(t)
		if tid == 0 {
			continue
		}
		dbp.CurrentThread, _ = dbp.addThread(tid)
	}

	fnCatchExceptionRaise = func(task C.int, thread C.int, exception C.exception_type_t, code C.exception_data_t, ncode C.mach_msg_type_number_t) int {
		log.Printf("task:%d, thread:%d, exception:%d", task, thread, exception)

		err := taskSuspend(dbp.Pid)
		if err != nil {
			log.Fatal(err)
		}

		tid := int(thread)

		status := syscall.WaitStatus(0)
		if exception == 6 {
			status = 0x57f //simulate stop trap
		} else {
			log.Fatal(fmt.Sprintf("exception: %d", int(exception)))
		}
		evt := &trapEvent{tid, &status, nil}
		if _, ok := dbp.Threads[tid]; !ok {
			dbp.addThread(tid)
		}
		dbp.chTrap <- evt

		//regs, _ := th.GetRegs()
		//log.Printf("exp:%d, rip:0x%x", exp, regs.Rip())

		//log.Printf("regs:%#v", regs)
		//log.Printf("rip:0x%x", regs.Rip())
		return 0
	}

	go waitroutine(&dbp)
	go C.server()

	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil, err
	}

	dbp.Process = proc

	if !attach {
		//only use ptrace for startup
		err = syscall.PtraceDetach(pid)
		if err != nil {
			return nil, err
		}
	}

	err = dbp.LoadInformation()
	if err != nil {
		return nil, err
	}

	return &dbp, nil
}

// Resume process.
func (dbp *DebuggedProcess) Continue() error {
	if err := taskResume(dbp.Pid); err != nil {
		log.Fatal(err)
	}

	fn := func() error {
		wpid, _, err := trapWait(dbp, -1)
		if err != nil {
			return err
		}
		println("trapWait:", wpid)
		return handleBreakpoint(dbp, wpid)
	}
	return dbp.run(fn)
}

// Steps through process.
func (dbp *DebuggedProcess) Step() (err error) {
	fn := func() error {
		return dbp.CurrentThread.Step()
	}

	return dbp.run(fn)
}

// Step over function calls.
func (dbp *DebuggedProcess) Next() error {
	fn := func() error {
		return dbp.CurrentThread.Next()
	}

	return dbp.run(fn)
}

func Attach(pid int) (*DebuggedProcess, error) {
	dbp, err := newDebugProcess(pid, true)
	if err != nil {
		return nil, err
	}

	return dbp, nil
}

func (dbp *DebuggedProcess) Detach() error {
	return macherr(C.int(C.detach(C.int(dbp.Pid))))
}

func taskSuspend(pid int) error {
	return macherr(C.tasksuspend(C.int(pid)))
}

func taskResume(pid int) error {
	return macherr(C.taskresume(C.int(pid)))
}
