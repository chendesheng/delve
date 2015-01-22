package proctl

//#include "mach_darwin.h"
import "C"

import (
	"errors"
	"unsafe"
)

const (
	FLAGS_TF = 0x100 // x86 single-step processor flag
)

func macherr(n C.int) error {
	if n == 0 { //success
		return nil
	} else {
		return errors.New(C.GoString(C.mach_error_string(C.mach_error_t(n))))
	}
}

type Regs C.Regs

func (r *Regs) PC() uint64 {
	return uint64(r.__rip)
}

func (r *Regs) SP() uint64 {
	return uint64(r.__rsp)
}

func (r *Regs) SetPC(tid int, pc uint64) error {
	r.__rip = C.__uint64_t(pc)
	return macherr(C.setregs(C.int(tid), (*C.Regs)(unsafe.Pointer(r))))
}

func (r *Regs) Rflags() uint64 {
	return uint64(r.__rflags)
}

func (r *Regs) SetRflags(tid int, rflags uint64) error {
	r.__rflags = C.__uint64_t(rflags)
	return macherr(C.setregs(C.int(tid), (*C.Regs)(unsafe.Pointer(r))))
}

func registers(tid int) (Registers, error) {
	r := Regs{}
	if err := macherr(C.getregs(C.int(tid), (*C.Regs)(unsafe.Pointer(&r)))); err == nil {
		return &r, nil
	} else {
		return nil, err
	}
}

func writeMemory(tid int, addr uintptr, data []byte) (int, error) {
	if err := macherr(C.vmwrite(C.int(tid), C.ulong(addr), unsafe.Pointer(&data[0]), C.int(len(data)))); err != nil {
		return 0, err
	} else {
		return len(data), nil
	}
}

func readMemory(tid int, addr uintptr, data []byte) (int, error) {
	outsize := C.ulong(0)
	if err := macherr(C.vmread(C.int(tid), C.ulong(addr), C.int(len(data)), unsafe.Pointer(&data[0]), &outsize)); err != nil {
		return 0, err
	} else {
		return int(outsize), nil
	}

}

func readByte(tid int, addr uint64) (byte, error) {
	data := make([]byte, 1, 1)
	_, err := readMemory(tid, uintptr(addr), data)
	if err != nil {
		return 0, err
	} else {
		return data[0], nil
	}
}

func writeByte(tid int, addr uint64, b byte) error {
	data := make([]byte, 1, 1)
	data[0] = b
	_, err := writeMemory(tid, uintptr(addr), data)
	return err
}

//TODO
func clearHardwareBreakpoint(reg, tid int) error {
	return nil
}

func singleStep(tid int) error {
	regs, err := registers(tid)
	if err != nil {
		return err
	}

	err = regs.SetRflags(tid, regs.Rflags()|FLAGS_TF)
	if err != nil {
		return err
	}

	err = macherr(C.int(C.thread_resume(C.thread_act_t(tid))))
	if err != nil {
		return err
	}

	return nil
}

func ptraceCont(tid int) error {
	regs, err := registers(tid)
	if err != nil {
		return err
	}

	if rflags := regs.Rflags(); rflags&FLAGS_TF != 0 {
		regs.SetRflags(tid, rflags&^FLAGS_TF)
	}

	return macherr(C.int(C.thread_resume(C.thread_act_t(tid))))
}
