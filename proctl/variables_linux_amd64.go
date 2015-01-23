package proctl

func (thread *ThreadContext) readMemory(addr uintptr, size uintptr) ([]byte, error) {
	buf := make([]byte, size)

	_, err := readMemory(thread.Id, addr, buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}
