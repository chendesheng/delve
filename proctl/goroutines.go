package proctl

type Registers interface {
	PC() uint64
	SP() uint64
	SetPC(int, uint64) error
	Rflags() uint64
	SetRflags(int, uint64) error
}

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
