package proctl

import "fmt"

func (dbp *DebuggedProcess) setBreakpoint(addr uint64, gid int) (*Breakpoint, error) {
	var f, l, fn = dbp.GoSymTable.PCToLine(uint64(addr))
	if fn == nil {
		return nil, InvalidAddressError{address: addr}
	}

	bp := dbp.Breakpoints[addr]
	if bp == nil {
		originalData, err := dbp.readMemory(uintptr(addr), 1)
		if err != nil {
			return nil, err
		}

		_, err = dbp.writeMemory(uintptr(addr), []byte{0xCC})
		if err != nil {
			return nil, err
		}

		bp = dbp.newBreakpoint(fn.Name, f, l, addr, originalData)
		dbp.Breakpoints[addr] = bp
	}

	if !bp.belongsTo(gid) {
		bp.goroutines = append(bp.goroutines, gid)
	}

	return bp, nil
}

func (dbp *DebuggedProcess) clearBreakpoint(addr uint64, gid int) (*Breakpoint, error) {
	// Check for software breakpoint
	if bp, ok := dbp.Breakpoints[addr]; ok {
		maxindex := len(bp.goroutines) - 1
		for i, id := range bp.goroutines {
			if id == gid {
				bp.goroutines[i] = bp.goroutines[maxindex]
				bp.goroutines = bp.goroutines[:maxindex]
				break
			}
		}

		if len(bp.goroutines) == 0 {
			if _, err := dbp.writeMemory(uintptr(bp.Addr), bp.OriginalData); err != nil {
				return nil, fmt.Errorf("could not clear breakpoint %s", err)
			}
			delete(dbp.Breakpoints, addr)
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
