package proctl

//#include "mach_darwin.h"
//#include <libproc.h>
//#include <sys/ptrace.h>
import "C"

import (
	"debug/macho"
	"errors"
	"fmt"
	"os"
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
	tid    int
	status *syscall.WaitStatus
	err    error
}

type debuggedProcess struct {
	chTrap chan *trapEvent
}

func (dbp *DebuggedProcess) findExecutable() (exefile, error) {
	procpath := make([]byte, 2048)
	sz := len(procpath)
	sz = int(C.proc_pidpath(C.int(dbp.Pid), unsafe.Pointer(&procpath[0]), C.uint32_t(sz)))
	if sz <= 0 {
		return exefile{}, errors.New("proc_pidpath error")
	}

	f, err := os.OpenFile(string(procpath), 0, os.ModePerm)
	if err != nil {
		return exefile{}, err
	}

	machofile, err := macho.NewFile(f)
	if err != nil {
		return exefile{}, err
	}

	data, err := machofile.DWARF()
	if err != nil {
		return exefile{}, err
	}
	dbp.Dwarf = data

	return exefile{machofile}, nil
}

func (dbp *DebuggedProcess) addThread(tid int) (*ThreadContext, error) {
	return nil, errors.New("Not implemented")
}

func (dbp *DebuggedProcess) AttachThread(tid int) (*ThreadContext, error) {
	return nil, errors.New("Not implemented")
}

func addNewThread(dbp *DebuggedProcess, pid int) error {
	return errors.New("Not implemented")
}

func stopped(pid int) bool {
	return false
}

func (dbp *DebuggedProcess) RequestManualStop() {
}

func waitroutine(dbp *DebuggedProcess) {
	pid, status, err := wait(dbp.Pid, 0)
	dbp.chTrap <- &trapEvent{pid, status, err}
}

func trapWait(dbp *DebuggedProcess, pid int) (int, *syscall.WaitStatus, error) {
	for {
		evt := <-dbp.chTrap
		wpid, status, err := evt.tid, evt.status, evt.err

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
			return -1, status, ProcessExitedError{wpid}
		}

		//
		//		if status.StopSignal() == syscall.SIGTRAP && status.TrapCause() == syscall.PTRACE_EVENT_CLONE {
		//			err = addNewThread(dbp, wpid)
		//			if err != nil {
		//				return -1, nil, err
		//			}
		//			continue
		//		}

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
	// Loop through all threads and ensure that we stop all of them
	for _, th := range dbp.Threads {
		return macherr(C.int(C.thread_suspend(C.thread_act_t(th.Id))))
	}

	return nil
}
