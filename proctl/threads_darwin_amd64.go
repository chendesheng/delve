package proctl

//#include "mach_darwin.h"
import "C"

import (
	"errors"
	"log"
	"runtime/debug"
	"unsafe"
)

const (
	FLAGS_TF = 0x100 // x86 single-step processor flag
)

func macherr(n C.int) error {
	if n == 0 { //success
		return nil
	} else {
		println(string(debug.Stack()))
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

func (r *Regs) GS() uint64 {
	return uint64(r.__gs)
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

func (r *Regs) rax() uint64 {
	return uint64(r.__rax)
}

func mustGetRegs(tid int) Registers {
	regs, err := registers(tid)
	if err != nil {
		log.Fatal(err)
	}

	return regs
}

func registers(tid int) (Registers, error) {
	r := Regs{}
	if err := macherr(C.getregs(C.int(tid), (*C.Regs)(unsafe.Pointer(&r)))); err == nil {
		return &r, nil
	} else {
		return nil, err
	}
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

	return nil
}
