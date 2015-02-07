package proctl

import (
	"encoding/binary"
	"fmt"
	"log"
	"runtime"

	"github.com/chendesheng/delve/dwarf/frame"
)

type Goroutine struct {
	dbp    *DebuggedProcess
	id     int
	tid    int
	chwait chan struct{}
	chcont chan chan struct{}
}

func (g *Goroutine) pc() (uint64, error) {
	regs, err := registers(g.tid)
	if err != nil {
		return 0, err
	}

	return regs.PC(), nil

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

		if !fde.Cover(pc) && pc != ret {
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
	regs, err := registers(g.tid)
	if err != nil {
		return fmt.Errorf("could not get registers %s", err)
	}
	log.Printf("cont:%#v", regs.PC())

	if _, ok := g.dbp.Breakpoints[regs.PC()-1]; ok {
		err := g.step()
		if err != nil {
			return fmt.Errorf("could not step %s", err)
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
		g.removeSingleStep()
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

	originalData, err := g.dbp.readMemory(uintptr(addr), 1)
	if err != nil {
		return err
	}
	_, err = g.dbp.writeMemory(uintptr(addr), []byte{0xCC})
	if err != nil {
		return err
	}

	// Ensure we cleanup after ourselves no matter what.
	defer func() {
		if _, err := g.dbp.writeMemory(uintptr(addr), originalData); err != nil {
			log.Fatal(err)
		}
	}()

	for {
		g.wait()

		regs, _ := registers(g.tid)
		pc = regs.PC()

		log.Printf("continueToReturnAddress:pc:0x%x,addr:0x%x", pc, addr)
		if (pc - 1) == addr {
			regs.SetPC(g.tid, addr)
			break
		}
	}

	return nil
}
