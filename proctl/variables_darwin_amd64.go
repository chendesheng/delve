package proctl

func (thread *ThreadContext) readMemory(addr uintptr, size uintptr) ([]byte, error) {
	buf := make([]byte, size)
	if size == 0 {
		return buf, nil
	}

	_, err := readMemory(thread.Process.Pid, addr, buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}
