package proctl

import "fmt"

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
	temp         bool
	count        int
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
	if _, ok := dbp.Breakpoints[addr]; ok {
		return true
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
