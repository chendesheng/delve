package proctl

//#include "mach_darwin.h"
import "C"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"runtime"
	"runtime/debug"
	"unsafe"

	"github.com/chendesheng/delve/dwarf/frame"
)

const (
	FLAGS_TF = 0x100 // x86 single-step processor flag
)

func macherr(n C.int) error {
	if n == 0 { //success
		return nil
	} else {
		println(string(debug.Stack()))
		return errors.New(C.GoString(C.mach_error_string(C.mach_error_t(n))))
	}
}

type Regs C.Regs

func (r *Regs) PC() uint64 {
	return uint64(r.__rip)
}

func (r *Regs) SP() uint64 {
	return uint64(r.__rsp)
}

func (r *Regs) SetPC(tid int, pc uint64) error {
	r.__rip = C.__uint64_t(pc)
	return macherr(C.setregs(C.int(tid), (*C.Regs)(unsafe.Pointer(r))))
}

func (r *Regs) Rflags() uint64 {
	return uint64(r.__rflags)
}

func (r *Regs) SetRflags(tid int, rflags uint64) error {
	r.__rflags = C.__uint64_t(rflags)
	return macherr(C.setregs(C.int(tid), (*C.Regs)(unsafe.Pointer(r))))
}

func mustGetRegs(tid int) Registers {
	regs, err := registers(tid)
	if err != nil {
		log.Fatal(err)
	}

	return regs
}

func registers(tid int) (Registers, error) {
	r := Regs{}
	if err := macherr(C.getregs(C.int(tid), (*C.Regs)(unsafe.Pointer(&r)))); err == nil {
		return &r, nil
	} else {
		return nil, err
	}
}

func (g *Goroutine) next() error {
	pc, err := g.pc()
	if err != nil {
		return err
	}

	if bp, ok := g.dbp.Breakpoints[pc-1]; ok {
		pc = bp.Addr
	}

	fde, err := g.dbp.FrameEntries.FDEForPC(pc)
	if err != nil {
		return err
	}

	_, l, _ := g.dbp.GoSymTable.PCToLine(pc)
	ret := g.ReturnAddressFromOffset(fde.ReturnAddressOffset(pc))
	for {
		if err = g.step(); err != nil {
			return err
		}

		regs, err := registers(g.tid)
		if err != nil {
			return err
		}
		//pc := regs.PC()
		pc, rflags := regs.PC(), regs.Rflags()
		log.Printf("pc: 0x%x", pc)
		log.Printf("rflags: 0x%x", rflags)
		log.Printf("ret: 0x%x", ret)

		if !fde.Cover(pc) && pc != ret { //goto different function
			log.Print("continueToReturnAddress")
			if err := g.continueToReturnAddress(pc, fde); err != nil {
				if _, ok := err.(InvalidAddressError); !ok {
					return err
				}
			}
			if pc, err = g.pc(); err != nil {
				return err
			}
		}

		if _, nl, _ := g.dbp.GoSymTable.PCToLine(pc); nl != l {
			//log.Printf("line:%d", nl)
			break
		}
	}

	return nil
}

func (g *Goroutine) cont() error {
	err := g.next()
	if err != nil {
		if _, ok := err.(frame.ErrUnknownFDE); !ok {
			return err
		}
	}

	g.wait()
	return nil
}

func (g *Goroutine) step() error {
	regs, err := registers(g.tid)
	if err != nil {
		return err
	}
	log.Printf("step:%#v", regs.PC())

	bp, ok := g.dbp.Breakpoints[regs.PC()-1]
	if ok {
		// Clear the breakpoint so that we can continue execution.
		_, err = g.dbp.clearBreakpoint(bp.Addr)
		if err != nil {
			return err
		}

		log.Printf("SetPC:0x%x", bp.Addr)
		// Reset program counter to our restored instruction.
		err = regs.SetPC(g.tid, bp.Addr)
		if err != nil {
			return fmt.Errorf("could not set registers %s", err)
		}

		// Restore breakpoint now that we have passed it.
		defer func() {
			log.Printf("add breakpoint back:%#v", bp.Addr)
			g.dbp.setBreakpoint(bp.Addr)
		}()
	}

	err = regs.SetRflags(g.tid, regs.Rflags()|FLAGS_TF)
	if err != nil {
		return fmt.Errorf("step failed: %s", err.Error())
	}

	g.wait()

	//	regs, err = registers(g.tid)
	//	if err != nil {
	//		return err
	//	}
	//
	//	if rflags := regs.Rflags(); rflags&FLAGS_TF != 0 {
	//		log.Printf("SetRflags:0x%x", rflags)
	//		regs.SetRflags(g.tid, rflags&^FLAGS_TF)
	//	}

	return nil
}

func (g *Goroutine) removeSingleStep() {
	regs, err := registers(g.tid)
	if err != nil {
		log.Print(err)
		return
	}

	if rflags := regs.Rflags(); rflags&FLAGS_TF != 0 {
		log.Printf("SetRflags:0x%x", rflags)
		regs.SetRflags(g.tid, rflags&^FLAGS_TF)
	}
}

func (g *Goroutine) wait() {
	//log.Print("write chwait")
	g.chwait <- struct{}{}

	//log.Print("read chcont")
	if chwait, ok := <-g.chcont; ok {
		g.chwait = chwait

		g.removeSingleStep()
	} else {
		runtime.Goexit()
	}

}

// Takes an offset from RSP and returns the address of the
// instruction the currect function is going to return to.
func (g *Goroutine) ReturnAddressFromOffset(offset int64) uint64 {
	regs, err := registers(g.tid)
	if err != nil {
		panic("Could not obtain register values")
	}

	retaddr := int64(regs.SP()) + offset
	data, err := g.dbp.readMemory(uintptr(retaddr), 8)
	if err != nil {
		panic("Could not read from memory")
	}
	return binary.LittleEndian.Uint64(data)
}

func (g *Goroutine) continueToReturnAddress(pc uint64, fde *frame.FrameDescriptionEntry) error {
	// Our offset here is be 0 because we
	// have stepped into the first instruction
	// of this function. Therefore the function
	// has not had a chance to modify its' stack
	// and change our offset.
	addr := g.ReturnAddressFromOffset(0)

	if _, err := g.dbp.setBreakpoint(addr); err != nil {
		return err
	}

	// Ensure we cleanup after ourselves no matter what.
	defer func() {
		if _, err := g.dbp.clearBreakpoint(addr); err != nil {
			log.Print(err)
		}
	}()

	for {
		g.wait()

		regs, _ := registers(g.tid)
		pc = regs.PC()

		log.Printf("continueToReturnAddress:pc:0x%x,addr:0x%x", pc, addr)
		if _, ok := g.dbp.Breakpoints[pc-1]; ok {
			regs.SetPC(g.tid, pc-1)
		}

		if (pc - 1) == addr {
			break
		}
	}

	return nil
}
