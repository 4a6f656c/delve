package native

import (
	"fmt"

	"github.com/go-delve/delve/pkg/dwarf/op"
	"github.com/go-delve/delve/pkg/dwarf/regnum"
	"github.com/go-delve/delve/pkg/proc"
	"github.com/go-delve/delve/pkg/proc/amd64util"
	"github.com/go-delve/delve/pkg/proc/obsdutil"
)

// SetPC sets RIP to the value specified by 'pc'.
func (thread *nativeThread) setPC(pc uint64) error {
	ir, err := registers(thread)
	if err != nil {
		return err
	}
	r := ir.(*obsdutil.AMD64Registers)
	r.Regs.RIP = int64(pc)
	thread.dbp.execPtraceFunc(func() { err = ptraceSetRegs(thread.ID, r.Regs) })
	return err
}

// SetReg changes the value of the specified register.
func (thread *nativeThread) SetReg(regNum uint64, reg *op.DwarfRegister) (err error) {
	ir, err := registers(thread)
	if err != nil {
		return err
	}
	r := ir.(*obsdutil.AMD64Registers)
	switch regNum {
	case regnum.AMD64_Rip:
		r.Regs.RIP = int64(reg.Uint64Val)
	case regnum.AMD64_Rsp:
		r.Regs.RSP = int64(reg.Uint64Val)
	case regnum.AMD64_Rdx:
		r.Regs.RDX = int64(reg.Uint64Val)
	default:
		return fmt.Errorf("changing register %d not implemented", regNum)
	}
	thread.dbp.execPtraceFunc(func() { err = ptraceSetRegs(thread.ID, r.Regs) })
	return
}

func registers(thread *nativeThread) (proc.Registers, error) {
	var (
		regs *obsdutil.AMD64PtraceRegs
		tcb  uintptr
		err  error
	)
	thread.dbp.execPtraceFunc(func() { regs, err = ptraceRegs(thread.ID) })
	if err != nil {
		return nil, err
	}
	//thread.dbp.execPtraceFunc(func() { tcb, err = ptraceThreadTCB(thread.dbp.pid, thread.ID) })
	//if err != nil {
	//	return nil, err
	//}
	r := obsdutil.NewAMD64Registers(regs, tcb, func(r *obsdutil.AMD64Registers) error {
		var fpRegSet amd64util.AMD64Xstate
		var floatLoadError error
		r.FPRegs, fpRegSet, floatLoadError = thread.fpRegisters()
		r.FPRegSet = &fpRegSet
		return floatLoadError
	})
	return r, nil
}

func (thread *nativeThread) fpRegisters() (regs []proc.Register, fpregs amd64util.AMD64Xstate, err error) {
	thread.dbp.execPtraceFunc(func() { fpregs, err = ptraceFPRegs(thread.ID) })
	if err != nil {
		err = fmt.Errorf("could not get floating point registers: %v", err.Error())
	}
	regs = fpregs.Decode()
	return
}
