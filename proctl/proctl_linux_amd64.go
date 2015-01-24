package proctl

import (
	"debug/elf"
	"fmt"
	"log"
	"os"
	"syscall"
)

const (
	S_GOSYMTAB    = ".gosymtab"
	S_GOPCLNTAB   = ".gopclntab"
	S_TEXT        = ".text"
	S_DEBUG_FRAME = ".debug_frame"
)

const (
	STATUS_SLEEPING   = 'S'
	STATUS_RUNNING    = 'R'
	STATUS_TRACE_STOP = 't'
)

type exefile struct {
	*elf.File
}

type debuggedProcess struct {
}

func (dbp *DebuggedProcess) addThread(tid int) (*ThreadContext, error) {
	err := syscall.PtraceSetOptions(tid, syscall.PTRACE_O_TRACECLONE)
	if err == syscall.ESRCH {
		_, _, err = wait(tid, 0)
		if err != nil {
			return nil, fmt.Errorf("error while waiting after adding thread: %d %s", tid, err)
		}

		err := syscall.PtraceSetOptions(tid, syscall.PTRACE_O_TRACECLONE)
		if err != nil {
			return nil, fmt.Errorf("could not set options for new traced thread %d %s", tid, err)
		}
	}

	dbp.Threads[tid] = &ThreadContext{
		Id:      tid,
		Process: dbp,
	}

	return dbp.Threads[tid], nil
}

func stopped(pid int) bool {
	f, err := os.Open(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	defer f.Close()

	var (
		p     int
		comm  string
		state rune
	)
	fmt.Fscanf(f, "%d %s %c", &p, &comm, &state)
	if state == STATUS_TRACE_STOP {
		return true
	}
	return false
}

func (dbp *DebuggedProcess) findExecutable() (exefile, error) {
	procpath := fmt.Sprintf("/proc/%d/exe", dbp.Pid)

	f, err := os.OpenFile(procpath, 0, os.ModePerm)
	if err != nil {
		return exefile{}, err
	}

	elffile, err := elf.NewFile(f)
	if err != nil {
		return exefile{}, err
	}

	data, err := elffile.DWARF()
	if err != nil {
		return exefile{}, err
	}
	dbp.Dwarf = data

	return exefile{elffile}, nil
}

func (dbp *DebuggedProcess) AttachThread(tid int) (*ThreadContext, error) {
	if thread, ok := dbp.Threads[tid]; ok {
		return thread, nil
	}

	err := syscall.PtraceAttach(tid)
	if err != nil && err != syscall.EPERM {
		// Do not return err if err == EPERM,
		// we may already be tracing this thread due to
		// PTRACE_O_TRACECLONE. We will surely blow up later
		// if we truly don't have permissions.
		return nil, fmt.Errorf("could not attach to new thread %d %s", tid, err)
	}

	pid, status, err := wait(tid, 0)
	if err != nil {
		return nil, err
	}

	if status.Exited() {
		return nil, fmt.Errorf("thread already exited %d", pid)
	}

	return dbp.addThread(tid)
}

func addNewThread(dbp *DebuggedProcess, pid int) error {
	// A traced thread has cloned a new thread, grab the pid and
	// add it to our list of traced threads.
	msg, err := syscall.PtraceGetEventMsg(pid)
	if err != nil {
		return fmt.Errorf("could not get event message: %s", err)
	}
	fmt.Println("new thread spawned", msg)

	_, err = dbp.addThread(int(msg))
	if err != nil {
		return err
	}

	err = syscall.PtraceCont(int(msg), 0)
	if err != nil {
		return fmt.Errorf("could not continue new thread %d %s", msg, err)
	}

	err = syscall.PtraceCont(pid, 0)
	if err != nil {
		return fmt.Errorf("could not continue stopped thread %d %s", pid, err)
	}

	return nil
}

func (dbp *DebuggedProcess) RequestManualStop() {
	dbp.halt = true
	for _, th := range dbp.Threads {
		if stopped(th.Id) {
			continue
		}
		syscall.Tgkill(dbp.Pid, th.Id, syscall.SIGSTOP)
	}
	dbp.running = false
}

func trapWait(dbp *DebuggedProcess, pid int) (int, *syscall.WaitStatus, error) {
	for {
		wpid, status, err := wait(pid, 0)
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
		if status.StopSignal() == syscall.SIGTRAP && status.TrapCause() == syscall.PTRACE_EVENT_CLONE {
			err = addNewThread(dbp, wpid)
			if err != nil {
				return -1, nil, err
			}
			continue
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
	wpid, err := syscall.Wait4(pid, &status, syscall.WALL|options, nil)
	return wpid, &status, err
}

// Ensure execution of every traced thread is halted.
func stopTheWorld(dbp *DebuggedProcess) error {
	// Loop through all threads and ensure that we
	// stop the rest of them, so that by the time
	// we return control to the user, all threads
	// are inactive. We send SIGSTOP and ensure all
	// threads are in in signal-delivery-stop mode.
	for _, th := range dbp.Threads {
		if stopped(th.Id) {
			continue
		}
		err := syscall.Tgkill(dbp.Pid, th.Id, syscall.SIGSTOP)
		if err != nil {
			return err
		}
		pid, _, err := wait(th.Id, syscall.WNOHANG)
		if err != nil {
			return fmt.Errorf("wait err %s %d", err, pid)
		}
	}

	return nil
}

// Returns a new DebuggedProcess struct with sensible defaults.
func newDebugProcess(pid int, attach bool) (*DebuggedProcess, error) {
	dbp := DebuggedProcess{
		Pid:         pid,
		Threads:     make(map[int]*ThreadContext),
		Breakpoints: make(map[uint64]*Breakpoint),
	}

	if attach {
		thread, err := dbp.AttachThread(pid)
		if err != nil {
			return nil, err
		}
		dbp.CurrentThread = thread
	} else {
		thread, err := dbp.addThread(pid)
		if err != nil {
			return nil, err
		}
		dbp.CurrentThread = thread
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil, err
	}

	dbp.Process = proc
	err = dbp.LoadInformation()
	if err != nil {
		return nil, err
	}

	return &dbp, nil
}

// Steps through process.
func (dbp *DebuggedProcess) Step() (err error) {
	var (
		th *ThreadContext
		ok bool
	)

	allm, err := dbp.CurrentThread.AllM()
	if err != nil {
		return err
	}

	fn := func() error {
		for _, m := range allm {
			log.Printf("m:%v", m)

			th, ok = dbp.Threads[m.procid]
			if !ok {
				th = dbp.Threads[dbp.Pid]
			}

			if m.blocked == 0 {
				err := th.Step()
				if err != nil {
					return err
				}
			}

		}

		return nil
	}

	return dbp.run(fn)
}

// Step over function calls.
func (dbp *DebuggedProcess) Next() error {
	var (
		th *ThreadContext
		ok bool
	)

	allm, err := dbp.CurrentThread.AllM()
	if err != nil {
		return err
	}

	fn := func() error {
		for _, m := range allm {
			th, ok = dbp.Threads[m.procid]
			if !ok {
				th = dbp.Threads[dbp.Pid]
			}

			if m.blocked == 1 {
				// Continue any blocked M so that the
				// scheduler can continue to do its'
				// job correctly.
				err := th.Continue()
				if err != nil {
					return err
				}
				continue
			}

			err := th.Next()
			if err != nil && err != syscall.ESRCH {
				return err
			}
		}
		return stopTheWorld(dbp)
	}
	return dbp.run(fn)
}

func Attach(pid int) (*DebuggedProcess, error) {
	dbp, err := newDebugProcess(pid, true)
	if err != nil {
		return nil, err
	}
	// Attach to all currently active threads.
	allm, err := dbp.CurrentThread.AllM()
	if err != nil {
		return nil, err
	}
	for _, m := range allm {
		if m.procid == 0 {
			continue
		}
		_, err := dbp.AttachThread(m.procid)
		if err != nil {
			return nil, err
		}
	}
	return dbp, nil
}

func (dbp *DebuggedProcess) Detach() error {
	return syscall.PtraceDetach(dbp.Process.Pid)
}
