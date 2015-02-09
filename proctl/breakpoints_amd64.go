package proctl

import (
	"fmt"
	"log"
)

// Represents a single breakpoint. Stores information on the break
// point including the byte of data that originally was stored at that
// address.
type Breakpoint struct {
	FunctionName string
	File         string
	Line         int
	Addr         uint64
	OriginalData []byte
	ID           int
	goroutines   []int //breakpoint belong to those goroutines, -1 means belong to all goroutines
}

func (bp *Breakpoint) isTemp() bool {
	return !bp.belongsTo(-1)
}

func (bp *Breakpoint) belongsTo(gid int) bool {
	log.Printf("belongsTo:%d\n", gid)

	for _, id := range bp.goroutines {
		if id == gid {
			return true
		}
	}

	return false
}

type BreakpointExistsError struct {
	file string
	line int
	addr uint64
}

func (bpe BreakpointExistsError) Error() string {
	return fmt.Sprintf("Breakpoint exists at %s:%d at %x", bpe.file, bpe.line, bpe.addr)
}

func (dbp *DebuggedProcess) BreakpointExists(addr uint64) bool {
	if bp, ok := dbp.Breakpoints[addr]; ok {
		return !bp.isTemp() //hide temp breakpoint
	}
	return false
}

func (dbp *DebuggedProcess) newBreakpoint(fn, f string, l int, addr uint64, data []byte) *Breakpoint {
	dbp.breakpointIDCounter++
	return &Breakpoint{
		FunctionName: fn,
		File:         f,
		Line:         l,
		Addr:         addr,
		OriginalData: data,
		ID:           dbp.breakpointIDCounter,
	}
}
