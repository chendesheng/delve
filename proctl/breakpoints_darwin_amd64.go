package proctl

import "fmt"

func (dbp *DebuggedProcess) setBreakpoint(addr uint64) (*Breakpoint, error) {
	var f, l, fn = dbp.GoSymTable.PCToLine(uint64(addr))
	if fn == nil {
		return nil, InvalidAddressError{address: addr}
	}

	// Fall back to software breakpoint. 0xCC is INT 3, software
	// breakpoint trap interrupt.
	originalData, err := dbp.readMemory(uintptr(addr), 1)
	if err != nil {
		return nil, err
	}
	_, err = dbp.writeMemory(uintptr(addr), []byte{0xCC})
	if err != nil {
		return nil, err
	}

	if !dbp.BreakpointExists(addr) {
		dbp.Breakpoints[addr] = dbp.newBreakpoint(fn.Name, f, l, addr, originalData)
	}
	return dbp.Breakpoints[addr], nil
}

func (dbp *DebuggedProcess) clearBreakpoint(addr uint64) (*Breakpoint, error) {
	// Check for software breakpoint
	if bp, ok := dbp.Breakpoints[addr]; ok {
		if _, err := dbp.writeMemory(uintptr(bp.Addr), bp.OriginalData); err != nil {
			return nil, fmt.Errorf("could not clear breakpoint %s", err)
		}
		delete(dbp.Breakpoints, addr)
		return bp, nil
	}
	return nil, fmt.Errorf("No breakpoint currently set for %#v", addr)
}

// Sets a hardware breakpoint by setting the contents of the
// debug register `reg` with the address of the instruction
// that we want to break at. There are only 4 debug registers
// DR0-DR3. Debug register 7 is the control register.
func setHardwareBreakpoint(reg, tid int, addr uint64) error {
	//TODO
	return fmt.Errorf("Not implemented")
}
