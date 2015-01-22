package proctl

import "fmt"

func (dbp *DebuggedProcess) setBreakpoint(tid int, addr uint64) (*Breakpoint, error) {
	var f, l, fn = dbp.GoSymTable.PCToLine(uint64(addr))
	if fn == nil {
		return nil, InvalidAddressError{address: addr}
	}
	if dbp.BreakpointExists(addr) {
		return nil, BreakpointExistsError{f, l, addr}
	}
	// Try and set a hardware breakpoint.
	for i, v := range dbp.HWBreakpoints {
		if v == nil {
			if err := setHardwareBreakpoint(i, tid, addr); err != nil {
				return nil, fmt.Errorf("could not set hardware breakpoint")
			}
			dbp.HWBreakpoints[i] = dbp.newBreakpoint(fn.Name, f, l, addr, nil)
			return dbp.HWBreakpoints[i], nil
		}
	}
	// Fall back to software breakpoint. 0xCC is INT 3, software
	// breakpoint trap interrupt.
	originalData := make([]byte, 1)
	if _, err := readMemory(tid, uintptr(addr), originalData); err != nil {
		return nil, err
	}
	_, err := writeMemory(tid, uintptr(addr), []byte{0xCC})
	if err != nil {
		return nil, err
	}
	dbp.Breakpoints[addr] = dbp.newBreakpoint(fn.Name, f, l, addr, originalData)
	return dbp.Breakpoints[addr], nil
}

func (dbp *DebuggedProcess) clearBreakpoint(tid int, addr uint64) (*Breakpoint, error) {
	// Check for hardware breakpoint
	for i, bp := range dbp.HWBreakpoints {
		if bp.Addr == addr {
			dbp.HWBreakpoints[i] = nil
			if err := clearHardwareBreakpoint(i, tid); err != nil {
				return nil, err
			}
			return bp, nil
		}
	}
	// Check for software breakpoint
	if bp, ok := dbp.Breakpoints[addr]; ok {
		if _, err := writeMemory(tid, uintptr(bp.Addr), bp.OriginalData); err != nil {
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
