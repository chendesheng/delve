package proctl

import "fmt"

func (dbp *DebuggedProcess) setBreakpoint(addr uint64) (*Breakpoint, error) {
	var f, l, fn = dbp.GoSymTable.PCToLine(uint64(addr))
	if fn == nil {
		return nil, InvalidAddressError{address: addr}
	}

	// breakpoint trap interrupt.
	originalData, err := dbp.readMemory(uintptr(addr), 1)
	if err != nil {
		return nil, err
	}

	_, err = dbp.writeMemory(uintptr(addr), []byte{0xCC})
	if err != nil {
		return nil, err
	}

	b := dbp.Breakpoints[addr]
	if b == nil {
		b = dbp.newBreakpoint(fn.Name, f, l, addr, originalData)
		dbp.Breakpoints[addr] = b
	}
	b.count++
	println("b.count:", b.count)
	return b, nil
}

func (dbp *DebuggedProcess) clearBreakpoint(addr uint64) (*Breakpoint, error) {
	// Check for software breakpoint
	if bp, ok := dbp.Breakpoints[addr]; ok {
		bp.count--
		println("bp.count:", bp.count)
		if bp.count <= 0 {
			delete(dbp.Breakpoints, addr)

			if _, err := dbp.writeMemory(uintptr(bp.Addr), bp.OriginalData); err != nil {
				return nil, fmt.Errorf("could not clear breakpoint %s", err)
			}
		}
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
