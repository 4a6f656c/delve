package obsdutil

import (
	"github.com/go-delve/delve/pkg/proc"
	"github.com/go-delve/delve/pkg/proc/amd64util"
)

// AMD64Registers implements the proc.Registers interface for the native/openbsd
// backend and core/openbsd backends, on AMD64.
type AMD64Registers struct {
	Regs     *AMD64PtraceRegs
	FPRegs   []proc.Register
	FPRegSet *amd64util.AMD64Xstate
	TCB	 uintptr

	loadFpRegs func(*AMD64Registers) error
}

func NewAMD64Registers(regs *AMD64PtraceRegs, tcb uintptr, loadFpRegs func(*AMD64Registers) error) *AMD64Registers {
	return &AMD64Registers{Regs: regs, TCB: tcb, loadFpRegs: loadFpRegs}
}

// AMD64PtraceRegs is the struct used by the openbsd kernel to return the
// general purpose registers for AMD64 CPUs.
// source: machine/reg.h
type AMD64PtraceRegs struct {
	RDI int64
	RSI int64
	RDX int64
	RCX int64
	R8 int64
	R9 int64
	R10 int64
	R11 int64
	R12 int64
	R13 int64
	R14 int64
	R15 int64
	RBP int64
	RBX int64
	RAX int64
	RSP int64
	RIP int64
	RFlags int64
	CS int64
	SS int64
	DS int64
	ES int64
	FS int64
	GS int64
}

// Slice returns the registers as a list of (name, value) pairs.
func (r *AMD64Registers) Slice(floatingPoint bool) ([]proc.Register, error) {
	var regs64 = []struct {
		k string
		v int64
	}{
		{"RDI", r.Regs.RDI},
		{"RSI", r.Regs.RSI},
		{"RDX", r.Regs.RDX},
		{"RCX", r.Regs.RCX},
		{"R8", r.Regs.R8},
		{"R9", r.Regs.R9},
		{"R10", r.Regs.R10},
		{"R11", r.Regs.R11},
		{"R12", r.Regs.R12},
		{"R13", r.Regs.R13},
		{"R14", r.Regs.R14},
		{"R15", r.Regs.R15},
		{"RBP", r.Regs.RBP},
		{"RBX", r.Regs.RBX},
		{"RAX", r.Regs.RAX},
		{"RSP", r.Regs.RSP},
		{"RIP", r.Regs.RIP},
		{"RFlags", r.Regs.RFlags},
		{"CS", r.Regs.CS},
		{"SS", r.Regs.SS},
		{"DS", r.Regs.DS},
		{"ES", r.Regs.ES},
		{"FS", r.Regs.FS},
		{"GS", r.Regs.GS},
	}
	out := make([]proc.Register, 0, len(regs64)+len(r.FPRegs))
	for _, reg := range regs64 {
		out = proc.AppendUint64Register(out, reg.k, uint64(reg.v))
	}
	var floatLoadError error
	if floatingPoint {
		if r.loadFpRegs != nil {
			floatLoadError = r.loadFpRegs(r)
			r.loadFpRegs = nil
		}
		out = append(out, r.FPRegs...)
	}
	return out, floatLoadError
}

// PC returns the value of RIP register.
func (r *AMD64Registers) PC() uint64 {
	return uint64(r.Regs.RIP)
}

// SP returns the value of RSP register.
func (r *AMD64Registers) SP() uint64 {
	return uint64(r.Regs.RSP)
}

func (r *AMD64Registers) BP() uint64 {
	return uint64(r.Regs.RBP)
}

// TLS returns the address of the thread local storage memory segment.
func (r *AMD64Registers) TLS() uint64 {
	return uint64(r.TCB)
}

// GAddr returns the address of the G variable if it is known, 0 and false
// otherwise.
func (r *AMD64Registers) GAddr() (uint64, bool) {
	return 0, false //uint64(r.Regs.R14), !r.isCGO
}

// Copy returns a copy of these registers that is guaranteed not to change.
func (r *AMD64Registers) Copy() (proc.Registers, error) {
	if r.loadFpRegs != nil {
		err := r.loadFpRegs(r)
		r.loadFpRegs = nil
		if err != nil {
			return nil, err
		}
	}
	var rr AMD64Registers
	rr.Regs = &AMD64PtraceRegs{}
	rr.FPRegSet = &amd64util.AMD64Xstate{}
	*(rr.Regs) = *(r.Regs)
	if r.FPRegSet != nil {
		*(rr.FPRegSet) = *(r.FPRegSet)
	}
	if r.FPRegs != nil {
		rr.FPRegs = make([]proc.Register, len(r.FPRegs))
		copy(rr.FPRegs, r.FPRegs)
	}
	return &rr, nil
}
