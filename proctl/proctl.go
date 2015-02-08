// Package proctl provides functions for attaching to and manipulating
// a process during the debug session.
package proctl

import (
	"debug/dwarf"
	"debug/gosym"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/chendesheng/delve/dwarf/frame"
	"github.com/chendesheng/delve/dwarf/reader"
)

// Struct representing a debugged process. Holds onto pid, register values,
// process struct and process state.
type DebuggedProcess struct {
	debuggedProcess
	Pid                 int
	Process             *os.Process
	Dwarf               *dwarf.Data
	GoSymTable          *gosym.Table
	FrameEntries        *frame.FrameDescriptionEntries
	HWBreakpoints       [4]*Breakpoint
	Breakpoints         map[uint64]*Breakpoint
	breakpointIDCounter int
	running             bool
	halt                bool
}

type ManualStopError struct{}

func (mse ManualStopError) Error() string {
	return "Manual stop requested"
}

func Launch(cmd []string) (*DebuggedProcess, error) {
	proc := exec.Command(cmd[0])
	proc.Args = cmd
	proc.Stdout = os.Stdout
	proc.Stderr = os.Stderr
	proc.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}

	if err := proc.Start(); err != nil {
		return nil, err
	}

	_, _, err := wait(proc.Process.Pid, 0)
	if err != nil {
		return nil, fmt.Errorf("waiting for target execve failed: %s", err)
	}

	return newDebugProcess(proc.Process.Pid, false)
}

func (dbp *DebuggedProcess) Running() bool {
	return dbp.running
}

// Find a location by string (file+line, function, breakpoint id, addr)
func (dbp *DebuggedProcess) FindLocation(str string) (uint64, error) {
	// File + Line
	if strings.ContainsRune(str, ':') {
		fl := strings.Split(str, ":")

		fileName, err := filepath.Abs(fl[0])
		if err != nil {
			return 0, err
		}

		line, err := strconv.Atoi(fl[1])
		if err != nil {
			return 0, err
		}

		pc, _, err := dbp.GoSymTable.LineToPC(fileName, line)
		if err != nil {
			return 0, err
		}
		return pc, nil
	} else {
		// Try to lookup by function name
		fn := dbp.GoSymTable.LookupFunc(str)
		if fn != nil {
			return fn.Entry, nil
		}

		// Attempt to parse as number for breakpoint id or raw address
		id, err := strconv.ParseUint(str, 0, 64)
		if err != nil {
			return 0, fmt.Errorf("unable to find location for %s", str)
		}

		// Use as breakpoint id
		for _, bp := range dbp.Breakpoints {
			// ID
			if uint64(bp.ID) == id {
				return bp.Addr, nil
			}
		}

		// Last resort, use as raw address
		return id, nil
	}
}

// Sets a breakpoint in the current thread.
func (dbp *DebuggedProcess) Break(addr uint64) (*Breakpoint, error) {
	return dbp.setBreakpoint(addr)
}

// Sets a breakpoint by location string (function, file+line, address)
func (dbp *DebuggedProcess) BreakByLocation(loc string) (*Breakpoint, error) {
	addr, err := dbp.FindLocation(loc)
	if err != nil {
		return nil, err
	}
	return dbp.Break(addr)
}

func (dbp *DebuggedProcess) PrintBreakpoints() {
	for _, bp := range dbp.Breakpoints {
		fmt.Printf("%d\t%#v\t%s:%d\t%s\n", bp.ID, bp.Addr, bp.File, bp.Line, bp.FunctionName)
	}
}

// Clears a breakpoint in the current thread.
func (dbp *DebuggedProcess) Clear(addr uint64) (*Breakpoint, error) {
	return dbp.clearBreakpoint(addr)
}

// Clears a breakpoint by location (function, file+line, address, breakpoint id)
func (dbp *DebuggedProcess) ClearByLocation(loc string) (*Breakpoint, error) {
	addr, err := dbp.FindLocation(loc)
	if err != nil {
		return nil, err
	}
	regs, err := registers(dbp.currentGoroutine.tid)
	if err != nil {
		return nil, err
	}
	if regs.PC()-1 == addr {
		regs.SetPC(dbp.currentGoroutine.tid, addr)
	}
	return dbp.clearBreakpoint(addr)
}

// Loop through all threads, printing their information
// to the console.
func (dbp *DebuggedProcess) PrintThreadInfo() error {
	threads, err := dbp.getThreads()
	if err != nil {
		return err
	}

	log.Printf("threads:%#v", threads)

	for _, th := range threads {
		regs, err := registers(th)
		if err != nil {
			return err
		}
		pc := regs.PC()

		f, l, fn := dbp.GoSymTable.PCToLine(pc)
		if fn != nil {
			fmt.Printf("Thread %d at %#v %s:%d %s\n", th, pc, f, l, fn.Name)
		} else {
			fmt.Printf("Thread %d at %#v\n", th, pc)
		}
	}
	return nil
}

type InvalidAddressError struct {
	address uint64
}

func (iae InvalidAddressError) Error() string {
	return fmt.Sprintf("Invalid address %#v\n", iae.address)
}

func (dbp *DebuggedProcess) CurrentPCForDisplay() (uint64, error) {
	pc, err := dbp.currentGoroutine.pc()
	if err != nil {
		return pc, err
	} else if _, ok := dbp.Breakpoints[pc-1]; ok {
		return pc - 1, err
	} else {
		return pc, err
	}
}

func (dbp *DebuggedProcess) CurrentPC() (uint64, error) {
	return dbp.currentGoroutine.pc()
}

// Returns the value of the named symbol.
func (dbp *DebuggedProcess) EvalSymbol(name string) (*Variable, error) {
	if strings.HasPrefix(name, "0x") {
		addr, err := strconv.ParseInt(name, 0, 64)
		if err != nil {
			return nil, err
		}
		d, err := dbp.readMemory(uintptr(addr), 8)
		return &Variable{name, "0x" + strconv.FormatUint(binary.LittleEndian.Uint64(d), 16), "uint64"}, nil
	} else {
		return dbp.currentGoroutine.EvalSymbol(name)
	}
}

// Returns a reader for the dwarf data
func (dbp *DebuggedProcess) DwarfReader() *reader.Reader {
	return reader.New(dbp.Dwarf)
}

func (dbp *DebuggedProcess) run(fn func() error) error {
	dbp.running = true
	dbp.halt = false
	defer func() { dbp.running = false }()
	if err := fn(); err != nil {
		if _, ok := err.(ManualStopError); !ok {
			return err
		}
	}
	return nil
}

type ProcessExitedError struct {
	pid int
}

func (pe ProcessExitedError) Error() string {
	return fmt.Sprintf("process %d has exited", pe.pid)
}

func (dbp *DebuggedProcess) parseDebugFrame(exe exefile, wg *sync.WaitGroup) {
	defer wg.Done()

	debugFrame, err := exe.Section(S_DEBUG_FRAME).Data()
	if err != nil {
		fmt.Println("could not get .debug_frame section", err)
		os.Exit(1)
	}

	dbp.FrameEntries = frame.Parse(debugFrame)
}

func (dbp *DebuggedProcess) obtainGoSymbols(exe exefile, wg *sync.WaitGroup) {
	defer wg.Done()

	var (
		symdat  []byte
		pclndat []byte
		err     error
	)

	if sec := exe.Section(S_GOSYMTAB); sec != nil {
		symdat, err = sec.Data()
		if err != nil {
			fmt.Println("could not get .gosymtab section", err)
			os.Exit(1)
		}
	}

	if sec := exe.Section(S_GOPCLNTAB); sec != nil {
		pclndat, err = sec.Data()
		if err != nil {
			fmt.Println("could not get .gopclntab section", err)
			os.Exit(1)
		}
	}

	pcln := gosym.NewLineTable(pclndat, exe.Section(S_TEXT).Addr)
	tab, err := gosym.NewTable(symdat, pcln)
	if err != nil {
		fmt.Println("could not get initialize line table", err)
		os.Exit(1)
	}

	dbp.GoSymTable = tab
}

// Finds the executable from /proc/<pid>/exe and then
// uses that to parse the following information:
// * Dwarf .debug_frame section
// * Dwarf .debug_line section
// * Go symbol table.
func (dbp *DebuggedProcess) LoadInformation() error {
	var (
		wg  sync.WaitGroup
		exe exefile
		err error
	)

	exe, err = dbp.findExecutable()
	if err != nil {
		return err
	}

	wg.Add(2)
	go dbp.parseDebugFrame(exe, &wg)
	go dbp.obtainGoSymbols(exe, &wg)

	wg.Wait()

	return nil
}

func (dbp *DebuggedProcess) Listen(handler func()) {
	defer func() {
		for _, g := range dbp.goroutines {
			close(g.chcont)
		}
	}()
	for evt := range dbp.chTrap {
		log.Printf("receive chTrap: %v", evt)

		if evt.typ != TE_EXCEPTION && evt.err != nil {
			log.Fatal(evt.err)
			return
		}

		if evt.gid == -1 {
			gid, err := dbp.getGoroutineId(evt.tid)
			if err != nil {
				log.Fatal(err)
			}
			evt.gid = gid
		}

		switch evt.typ {
		case TE_MANUAL, TE_BREAKPOINT:
			g, ok := dbp.goroutines[evt.gid]
			oldg := g
			if !ok {
				g = dbp.addGoroutine(evt.gid, evt.tid)
				dbp.currentGoroutine = g
				go func(g *Goroutine) {
					//log.Print("read chcont")
					g.chwait = <-g.chcont

					//log.Print("start handler:", g.id)
					handler()
				}(g)
			} else {
				dbp.currentGoroutine = g
			}

			if dbp.currentGoroutine != oldg {
				fmt.Printf("Switch to goroutine %d\n", g.id)
			}

			chwait := make(chan struct{})

			//continue handler
			//log.Print("write chcont")
			g.chcont <- chwait

			//wait for handler
			<-chwait
			//log.Print("read chwait")

			dbp.resume()
			//threadResume(g.tid)
		case TE_EXCEPTION:
			if evt.err != nil {
				fmt.Printf("Exception occurred: %s", evt.err.Error())
			} else {
				fmt.Print("Unknown exception occurred")
			}
			fmt.Print("Process exit")
			return
		case TE_EXIT:
			fmt.Println("Process exit normally")
			return
		}
	}
}
