package proctl

//#include "mach_darwin.h"
//#include <libproc.h>
//#include <sys/ptrace.h>
import "C"

import (
	"debug/macho"
	"errors"
	"log"
	"os"
	"reflect"
	"runtime/debug"
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

const (
	TE_BREAKPOINT = iota
	TE_SIGNAL
	TE_MANUAL
	TE_EXCEPTION
	TE_EXIT
)

type trapEvent struct {
	gid  int
	tid  int
	typ  int
	err  error
	data []byte
}

type debuggedProcess struct {
	chTrap           chan *trapEvent //notify when mach exception happens
	goroutines       map[int]*Goroutine
	currentGoroutine *Goroutine
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

func (dbp *DebuggedProcess) addGoroutine(gid int, tid int) *Goroutine {
	log.Printf("addGroutine:%d %d", gid, tid)

	dbp.goroutines[gid] = &Goroutine{
		id:     gid,
		dbp:    dbp,
		tid:    tid,
		chcont: nil,
	}

	return dbp.goroutines[gid]
}

func (dbp *DebuggedProcess) RequestManualStop() error {
	log.Print("RequestManualStop:", dbp.currentGoroutine.id)

	//err := syscall.Kill(dbp.Pid, syscall.SIGSTOP)
	//if err != nil {
	//	return err
	//}
	//wait(dbp.Pid, 0)
	dbp.sigstop = true
	//err := dbp.suspend()
	//if err != nil {
	//	return err
	//}

	if dbp.currentGoroutine.id == 0 {
		//find a goroutine from dbp.goroutines
		//for gid, g := range dbp.goroutines {
		//	if gid != 0 {
		//		dbp.currentGoroutine = g
		//		dbp.chTrap <- &trapEvent{
		//			gid: g.id,
		//			tid: g.tid,
		//			typ: TE_MANUAL,
		//		}
		//		return nil
		//	}
		//}

		////find a goroutine from allg
		//allg, err := dbp.allG()
		//if err != nil {
		//	return err
		//}

		//var g *G
		//for _, g = range allg {
		//	if g.id != 0 {
		//		break
		//	}
		//}

		ths, err := dbp.getThreads()
		if err != nil {
			return err
		}
		log.Print("ths:", ths)

		for _, th := range ths {
			regs, err := registers(th)
			log.Printf("regs:%#v", regs)
			if err != nil {
				return err
			}

			gid, err := dbp.getGoroutineId(th)
			if err != nil {
				return err
			}

			if gid > 0 {
				dbp.currentGoroutine = dbp.addGoroutine(gid, th)
				dbp.chTrap <- &trapEvent{
					gid: gid,
					tid: th,
					typ: TE_MANUAL,
				}
				return nil
			}

			//if g.stacklo <= regs.SP() && regs.SP() <= g.stackhi {
			//	break
			//}
		}
	}

	dbp.chTrap <- &trapEvent{
		gid: dbp.currentGoroutine.id,
		tid: dbp.currentGoroutine.tid,
		typ: TE_MANUAL,
	}
	return nil
}

func waitroutine(dbp *DebuggedProcess) {
	for {
		var status syscall.WaitStatus
		syscall.Wait4(dbp.Pid, &status, 0, nil)

		log.Print("Wait4:", status)
		if status.Exited() {
			dbp.chTrap <- &trapEvent{
				gid: 0,
				tid: 0,
				typ: TE_EXIT,
			}
			return
		}
	}
}

//func trapWait(dbp *DebuggedProcess, pid int) (int, *syscall.WaitStatus, error) {
//	for {
//		evt := <-dbp.chTrap
//		log.Printf("receive chTrap: %v", evt)
//
//		wpid, status, err := evt.id, evt.status, evt.err
//
//		if err != nil {
//			return -1, nil, fmt.Errorf("wait err %s %d", err, pid)
//		}
//
//		if wpid == 0 {
//			continue
//		}
//
//		if th, ok := dbp.Threads[wpid]; ok {
//			th.Status = status
//		}
//
//		if status.Exited() && wpid == dbp.Pid {
//			dbp.CurrentThread.Status = status
//			return -1, status, ProcessExitedError{wpid}
//		}
//
//		if status.StopSignal() == syscall.SIGTRAP {
//			log.Print("trapWait:SIGTRAP")
//			return wpid, status, nil
//		}
//
//		if status.StopSignal() == syscall.SIGSTOP && dbp.halt {
//			return -1, nil, ManualStopError{}
//		}
//	}
//}

func wait(pid, options int) (int, *syscall.WaitStatus, error) {
	var status syscall.WaitStatus
	wpid, err := syscall.Wait4(pid, &status, options, nil)
	return wpid, &status, err
}

var fnCatchExceptionRaise func(C.int, C.int, C.exception_type_t, C.exception_data_t, C.mach_msg_type_number_t) int

//export catch_exception_raise
func catch_exception_raise(eport C.int, thread C.int, task C.int, exception C.exception_type_t,
	code C.exception_data_t, ncode C.mach_msg_type_number_t) C.int {

	//log.Print("[exception rise]task:", task, " thread:", thread)
	return C.int(fnCatchExceptionRaise(task, thread, exception, code, ncode))
}

func (dbp *DebuggedProcess) getThreads() ([]int, error) {
	pths := uintptr(0)
	nth := 0
	err := macherr(C.getthreads(C.int(dbp.Pid), unsafe.Pointer(&pths), (*C.int)(unsafe.Pointer(&nth))))
	if err != nil {
		return nil, err
	}

	threads := make([]int32, 0)
	head := (*reflect.SliceHeader)(unsafe.Pointer(&threads))
	head.Data = pths
	head.Len = nth
	head.Cap = nth

	res := make([]int, 0)
	for _, th := range threads {
		if th != 0 {
			res = append(res, int(th))
		}
	}

	return res, nil
}

// Returns a new DebuggedProcess struct with sensible defaults.
func newDebugProcess(pid int, attach bool) (*DebuggedProcess, error) {
	dbp := DebuggedProcess{
		Pid:         pid,
		Breakpoints: make(map[uint64]*Breakpoint),
		debuggedProcess: debuggedProcess{
			goroutines: make(map[int]*Goroutine),
		},
	}
	dbp.chTrap = make(chan *trapEvent, 100)

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

	if err := dbp.suspend(); err != nil {
		return nil, err
	}

	log.Printf("threads:%#v", threads)

	//Put callback here because we need closure to access the dbp object. I don't like global variable.
	fnCatchExceptionRaise = func(task C.int, thread C.int, exception C.exception_type_t, code C.exception_data_t, ncode C.mach_msg_type_number_t) int {
		//This function should return ASAP, if it take too long will trigger go sched preemption mechanism.
		//Delay any time-consuming operation if possible

		//regs, _ := registers(int(thread))
		//log.Printf("task:%d, thread:0x%x, exception:%d, pc:0x%x", task, thread, exception, regs.PC())

		//It looks like suspend will not take effect until this function return
		err := dbp.suspend()
		if err != nil {
			log.Fatal(err)
		}

		tid := int(thread)

		evttype := 0
		if exception == 6 {
			evttype = TE_BREAKPOINT
		} else {
			evttype = TE_EXCEPTION
			//regs := mustGetRegs(tid)
			//log.Printf("exception regs:%#v", regs)
			//log.Fatal(fmt.Sprintf("exception: %d", int(exception)))
		}

		//This won't block because chTrap is buffered
		dbp.chTrap <- &trapEvent{
			gid: -1, // -1 means the receiver should find goroutine from tid itself, find goroutine id may takes too long time.
			tid: tid,
			typ: evttype,
		}

		return 0
	}

	//stop at start
	dbp.chTrap <- &trapEvent{
		gid: 0,
		tid: int(threads[0]),
		typ: TE_MANUAL,
	}

	//go waitroutine(&dbp)
	go C.server()

	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil, err
	}

	dbp.Process = proc

	if !attach {
		//only use ptrace for startup
		//err = syscall.PtraceDetach(pid)
		err := ptracecont(pid)
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

func ptracecont(pid int) error {
	log.Print("ptracecont()")

	_, _, err := syscall.Syscall6(syscall.SYS_PTRACE, syscall.PTRACE_CONT, uintptr(pid), 1, 0, 0, 0)
	if err != syscall.Errno(0) {
		return err
	}
	return nil
}

// Obtains register values from what Delve considers to be the current
// thread of the traced process.
func (dbp *DebuggedProcess) Registers() (Registers, error) {
	return registers(dbp.currentGoroutine.tid)
}

// Resume process.
func (dbp *DebuggedProcess) Continue() error {
	log.Println("Continue()")
	//err := dbp.currentGoroutine.next()
	//if err != nil {
	//	//ignore ErrUnknownFDE
	//	if _, ok := err.(frame.ErrUnknownFDE); !ok {
	//		return err
	//	}
	//}

	return dbp.currentGoroutine.cont()
}

// Steps through process.
func (dbp *DebuggedProcess) Step() (err error) {
	return dbp.currentGoroutine.step()
}

// Step over function calls.
func (dbp *DebuggedProcess) Next() error {
	log.Print("Next()")
	return dbp.currentGoroutine.next()
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

func (dbp *DebuggedProcess) resume() error {
	log.Print("resume()")
	return macherr(C.taskresume(C.int(dbp.Pid)))
}

func (dbp *DebuggedProcess) suspend() error {
	log.Print("suspend()")
	return macherr(C.tasksuspend(C.int(dbp.Pid)))
}

//func threadSuspend(tid int) error {
//	return macherr(C.int(C.thread_suspend(C.thread_act_t(tid))))
//}

//func threadResume(tid int) error {
//	return macherr(C.int(C.thread_resume(C.thread_act_t(tid))))
//}

func (dbp *DebuggedProcess) writeMemory(addr uintptr, data []byte) (int, error) {
	log.Printf("write memory:%#v, %#v", uint64(addr), data)
	log.Print(string(debug.Stack()))
	if err := macherr(C.vmwrite(C.int(dbp.Pid), C.ulong(addr), unsafe.Pointer(&data[0]), C.int(len(data)))); err != nil {
		return 0, err
	} else {
		return len(data), nil
	}
}

func (dbp *DebuggedProcess) readMemory(addr uintptr, size int) ([]byte, error) {
	data := make([]byte, size)
	outsize := C.ulong(0)

	if err := macherr(C.vmread(C.int(dbp.Pid), C.ulong(addr), C.int(len(data)), unsafe.Pointer(&data[0]), &outsize)); err != nil {
		return nil, err
	} else {
		return data, nil
	}
}
