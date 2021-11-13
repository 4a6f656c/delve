package native

/*
#include <machine/reg.h>
#include <sys/types.h>
#include <sys/ptrace.h>

#include <stdlib.h>

// Wrapper to avoid setting piod_addr via unsafe.Pointer, which results in
// bad things happening during garbage collection.
void ptrace_set_io_desc(struct ptrace_io_desc *piod, int op, unsigned long offs, caddr_t addr, unsigned long len) {
	piod->piod_op = op;
	piod->piod_offs = (void *)offs;
	piod->piod_addr = addr;
	piod->piod_len = len;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/go-delve/delve/pkg/proc/amd64util"
	"github.com/go-delve/delve/pkg/proc/obsdutil"
)

// ptraceAttach attaches to give given process.
func ptraceAttach(pid int) error {
	ret, err := C.ptrace(C.PT_ATTACH, C.int(pid), C.caddr_t(unsafe.Pointer(uintptr(0))), C.int(0))
	if ret == -1 {
		return fmt.Errorf("ptrace attach failed: %v", err)
	}
	return nil
}

// ptraceDetach detaches from the given process.
func ptraceDetach(pid int) error {
	ret, err := C.ptrace(C.PT_DETACH, C.int(pid), C.caddr_t(unsafe.Pointer(uintptr(1))), C.int(0))
	if ret == -1 {
		return fmt.Errorf("ptrace detach failed: %v", err)
	}
	return nil
}

// ptraceCont continues a ptraced process - the id may be either a PID or TID.
func ptraceCont(id, sig int) error {
	ret, err := C.ptrace(C.PT_CONTINUE, C.int(id), C.caddr_t(unsafe.Pointer(uintptr(1))), C.int(sig))
	if ret == -1 {
		return fmt.Errorf("ptrace continue failed: %v", err)
	}
	return nil
}

// ptraceStep steps a ptraced process - the id may be either a PID or TID.
func ptraceStep(id, sig int) error {
	ret, err := C.ptrace(C.PT_STEP, C.int(id), C.caddr_t(unsafe.Pointer(uintptr(1))), C.int(sig))
	if ret == -1 {
		return fmt.Errorf("ptrace step failed: %v", err)
	}
	return nil
}

// ptraceThreadIDs returns a slice containing the thread IDs for a process.
func ptraceThreadIDs(pid int) (tids []int32, err error) {
	var pts C.struct_ptrace_thread_state
	ret, err := C.ptrace(C.PT_GET_THREAD_FIRST, C.int(pid), C.caddr_t(unsafe.Pointer(&pts)), C.int(unsafe.Sizeof(pts)))
	if ret == -1 {
		return nil, fmt.Errorf("ptrace PT_GET_THREAD_FIRST failed: %v", err)
	}
	for pts.pts_tid != -1 {
		tids = append(tids, int32(pts.pts_tid))
		ret, err := C.ptrace(C.PT_GET_THREAD_NEXT, C.int(pid), C.caddr_t(unsafe.Pointer(&pts)), C.int(unsafe.Sizeof(pts)))
		if ret == -1 {
			return nil, fmt.Errorf("ptrace PT_GET_THREAD_NEXT failed: %v", err)
		}
	}
	return tids, nil
}

// ptraceThreadTCB returns the TCB address for the given thread ID in the specified process.
func ptraceThreadTCB(pid, tid int) (uintptr, error) {
	var pts C.struct_ptrace_thread_state
	ret, err := C.ptrace(C.PT_GET_THREAD_FIRST, C.int(pid), C.caddr_t(unsafe.Pointer(&pts)), C.int(unsafe.Sizeof(pts)))
	if ret == -1 {
		return 0, fmt.Errorf("ptrace PT_GET_THREAD_FIRST failed: %v", err)
	}
	for pts.pts_tid != -1 {
		if int(pts.pts_tid) == tid {
			return uintptr(pts.pts_tcb), nil
		}
		ret, err := C.ptrace(C.PT_GET_THREAD_NEXT, C.int(pid), C.caddr_t(unsafe.Pointer(&pts)), C.int(unsafe.Sizeof(pts)))
		if ret == -1 {
			return 0, fmt.Errorf("ptrace PT_GET_THREAD_NEXT failed: %v", err)
		}
	}
	return 0, errors.New("thread not found")
}

// ptraceProcessState returns the state of the given process.
func ptraceProcessState(pid int) (int, int, int, error) {
	var pts C.struct_ptrace_state
	ret, err := C.ptrace(C.PT_GET_PROCESS_STATE, C.int(pid), C.caddr_t(unsafe.Pointer(&pts)), C.int(unsafe.Sizeof(pts)))
	if ret == -1 {
		return 0, 0, 0, fmt.Errorf("ptrace PT_GET_PROCESS_STATE failed: %v", err)
	}
	return int(pts.pe_report_event), int(pts.pe_other_pid), int(pts.pe_tid), nil
}

// ptraceRegs returns the registers from the given process or thread.
func ptraceRegs(id int) (*obsdutil.AMD64PtraceRegs, error) {
	var regs C.struct_reg
	ret, err := C.ptrace(C.PT_GETREGS, C.int(id), C.caddr_t(unsafe.Pointer(&regs)), C.int(unsafe.Sizeof(regs)))
	if ret == -1 {
		return nil, fmt.Errorf("ptrace PT_GETREGS failed: %v", err)
	}
	ptRegs := &obsdutil.AMD64PtraceRegs{
		RDI:    int64(regs.r_rdi),
		RSI:    int64(regs.r_rsi),
		RDX:    int64(regs.r_rdx),
		RCX:    int64(regs.r_rcx),
		R8:     int64(regs.r_r8),
		R9:     int64(regs.r_r9),
		R10:    int64(regs.r_r10),
		R11:    int64(regs.r_r11),
		R12:    int64(regs.r_r12),
		R13:    int64(regs.r_r13),
		R14:    int64(regs.r_r14),
		R15:    int64(regs.r_r15),
		RBP:    int64(regs.r_rbp),
		RBX:    int64(regs.r_rbx),
		RAX:    int64(regs.r_rax),
		RSP:    int64(regs.r_rsp),
		RIP:    int64(regs.r_rip),
		RFlags: int64(regs.r_rflags),
		CS:     int64(regs.r_cs),
		SS:     int64(regs.r_ss),
		DS:     int64(regs.r_ds),
		ES:     int64(regs.r_es),
		FS:     int64(regs.r_fs),
		GS:     int64(regs.r_gs),
	}
	return ptRegs, nil
}

// ptraceRegs sets the registers for the given process or thread.
func ptraceSetRegs(id int, ptRegs *obsdutil.AMD64PtraceRegs) error {
	regs := C.struct_reg{
		r_rdi:    C.longlong(ptRegs.RDI),
		r_rsi:    C.longlong(ptRegs.RSI),
		r_rdx:    C.longlong(ptRegs.RDX),
		r_rcx:    C.longlong(ptRegs.RCX),
		r_r8:     C.longlong(ptRegs.R8),
		r_r9:     C.longlong(ptRegs.R9),
		r_r10:    C.longlong(ptRegs.R10),
		r_r11:    C.longlong(ptRegs.R11),
		r_r12:    C.longlong(ptRegs.R12),
		r_r13:    C.longlong(ptRegs.R13),
		r_r14:    C.longlong(ptRegs.R14),
		r_r15:    C.longlong(ptRegs.R15),
		r_rbp:    C.longlong(ptRegs.RBP),
		r_rbx:    C.longlong(ptRegs.RBX),
		r_rax:    C.longlong(ptRegs.RAX),
		r_rsp:    C.longlong(ptRegs.RSP),
		r_rip:    C.longlong(ptRegs.RIP),
		r_rflags: C.longlong(ptRegs.RFlags),
		r_cs:     C.longlong(ptRegs.CS),
		r_ss:     C.longlong(ptRegs.SS),
		r_ds:     C.longlong(ptRegs.DS),
		r_es:     C.longlong(ptRegs.ES),
		r_fs:     C.longlong(ptRegs.FS),
		r_gs:     C.longlong(ptRegs.GS),
	}
	ret, err := C.ptrace(C.PT_SETREGS, C.int(id), C.caddr_t(unsafe.Pointer(&regs)), C.int(unsafe.Sizeof(regs)))
	if ret == -1 {
		return fmt.Errorf("ptrace PT_SETREGS failed: %v", err)
	}
	return nil
}

// ptraceFPRegs returns the floating point registers from the given process or thread.
func ptraceFPRegs(id int) (amd64util.AMD64Xstate, error) {
	var fpregs C.struct_fpreg
	ret, err := C.ptrace(C.PT_GETFPREGS, C.int(id), C.caddr_t(unsafe.Pointer(&fpregs)), C.int(unsafe.Sizeof(fpregs)))
	if ret == -1 {
		return amd64util.AMD64Xstate{}, fmt.Errorf("ptrace PT_GETFPREGS failed: %v", err)
	}

	axs := amd64util.AMD64Xstate{
		AMD64PtraceFpRegs: amd64util.AMD64PtraceFpRegs{
			Cwd:      uint16(fpregs.fxstate.fx_fcw),
			Swd:      uint16(fpregs.fxstate.fx_fsw),
			Ftw:      uint16(fpregs.fxstate.fx_ftw),
			Fop:      uint16(fpregs.fxstate.fx_fop),
			Rip:      uint64(fpregs.fxstate.fx_rip),
			Rdp:      uint64(fpregs.fxstate.fx_rdp),
			Mxcsr:    uint32(fpregs.fxstate.fx_mxcsr),
			MxcrMask: uint32(fpregs.fxstate.fx_mxcsr_mask),
		},
	}
	for i := 0; i < 8; i++ {
		for j := 0; j < 2; j++ {
			idx := i*4 + j*2
			fpreg := uint64(fpregs.fxstate.fx_st[i][j])
			axs.AMD64PtraceFpRegs.StSpace[idx+0] = uint32(fpreg)
			axs.AMD64PtraceFpRegs.StSpace[idx+1] = uint32(fpreg >> 32)
		}
	}
	for i := 0; i < 16; i++ {
		for j := 0; j < 2; j++ {
			idx := (i*2 + j) * 8
			fpreg := uint64(fpregs.fxstate.fx_xmm[i][j])
			*((*uint64)(unsafe.Pointer(&axs.AMD64PtraceFpRegs.XmmSpace[idx]))) = fpreg
		}
	}

	return axs, nil
}

// ptraceSetFPRegs sets the floating point registers for the given process or thread.
func ptraceSetFPRegs(id int, axs *amd64util.AMD64Xstate) error {
	var fpregs C.struct_fpreg

	fpregs.fxstate.fx_fcw = C.ushort(axs.Cwd)
	fpregs.fxstate.fx_fsw = C.ushort(axs.Swd)
	fpregs.fxstate.fx_ftw = C.uchar(axs.Ftw)
	fpregs.fxstate.fx_fop = C.ushort(axs.Fop)
	fpregs.fxstate.fx_rip = C.ulonglong(axs.Rip)
	fpregs.fxstate.fx_rdp = C.ulonglong(axs.Rdp)
	fpregs.fxstate.fx_mxcsr = C.uint(axs.Mxcsr)
	fpregs.fxstate.fx_mxcsr_mask = C.uint(axs.MxcrMask)
	for i := 0; i < 8; i++ {
		for j := 0; j < 2; j++ {
			idx := i*4 + j*2
			fpreg1 := uint64(axs.AMD64PtraceFpRegs.StSpace[idx+0])
			fpreg2 := uint64(axs.AMD64PtraceFpRegs.StSpace[idx+1])
			fpregs.fxstate.fx_st[i][j] = C.ulonglong(fpreg2<<32 | fpreg1)
		}
	}
	for i := 0; i < 16; i++ {
		for j := 0; j < 2; j++ {
			idx := (i*2 + j) * 8
			fpreg := *((*uint64)(unsafe.Pointer(&axs.AMD64PtraceFpRegs.XmmSpace[idx])))
			fpregs.fxstate.fx_xmm[i][j] = C.ulonglong(fpreg)
		}
	}

	ret, err := C.ptrace(C.PT_SETFPREGS, C.int(id), C.caddr_t(unsafe.Pointer(&fpregs)), C.int(unsafe.Sizeof(fpregs)))
	if ret == -1 {
		return fmt.Errorf("ptrace PT_SETFPREGS failed: %v", err)
	}
	return nil
}

// ptraceReadAuxInfo reads ELF AuxInfo from a ptraced process.
func ptraceReadAuxInfo(id int, data []byte) (n int, err error) {
	var piod C.struct_ptrace_io_desc
	C.ptrace_set_io_desc(&piod, C.PIOD_READ_AUXV, C.ulong(0), C.caddr_t(unsafe.Pointer(&data[0])), C.ulong(len(data)))
	ret, err := C.ptrace(C.PT_IO, C.int(id), C.caddr_t(unsafe.Pointer(&piod)), C.int(unsafe.Sizeof(piod)))
	if ret == -1 {
		return 0, fmt.Errorf("ptrace PIOD_READ_AUXV failed: %v", err)
	}
	if int(piod.piod_len) > len(data) {
		panic("ptraceReadAuxInfo overread")
	}
	return int(piod.piod_len), nil
}

// ptraceReadData reads data from a ptraced process - id may be a PID or TID.
func ptraceReadData(id int, addr uintptr, data []byte) (n int, err error) {
	var piod C.struct_ptrace_io_desc
	C.ptrace_set_io_desc(&piod, C.PIOD_READ_I, C.ulong(addr), C.caddr_t(unsafe.Pointer(&data[0])), C.ulong(len(data)))
	ret, err := C.ptrace(C.PT_IO, C.int(id), C.caddr_t(unsafe.Pointer(&piod)), C.int(unsafe.Sizeof(piod)))
	if ret == -1 {
		return 0, fmt.Errorf("ptrace PIOD_READ_I failed: %v", err)
	}
	if int(piod.piod_len) > len(data) {
		panic("ptraceReadAuxInfo overread")
	}
	return int(piod.piod_len), nil
}

// ptraceWriteData writes data to a ptraced process - id may be a PID or TID.
func ptraceWriteData(id int, addr uintptr, data []byte) (n int, err error) {
	var piod C.struct_ptrace_io_desc
	C.ptrace_set_io_desc(&piod, C.PIOD_WRITE_I, C.ulong(addr), C.caddr_t(unsafe.Pointer(&data[0])), C.ulong(len(data)))
	ret, err := C.ptrace(C.PT_IO, C.int(id), C.caddr_t(unsafe.Pointer(&piod)), C.int(unsafe.Sizeof(piod)))
	if ret == -1 {
		return 0, fmt.Errorf("ptrace PIOD_WRITE_I failed: %v", err)
	}
	return int(piod.piod_len), nil
}
