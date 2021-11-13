package native

// #include <signal.h>
import "C"
import (
	"fmt"
	"unsafe"

	sys "golang.org/x/sys/unix"

	"github.com/go-delve/delve/pkg/proc"
	"github.com/go-delve/delve/pkg/proc/amd64util"
	"github.com/go-delve/delve/pkg/proc/obsdutil"
)

type waitStatus sys.WaitStatus

// osSpecificDetails hold OpenBSD specific process details.
type osSpecificDetails struct{}

func (t *nativeThread) stop() (err error) {
	if C.thrkill(C.pid_t(t.ID), C.int(sys.SIGSTOP), unsafe.Pointer(uintptr(0))) == -1 {
		return fmt.Errorf("stop failed on thread %d", t.ID)
	}
	return nil
}

func (t *nativeThread) Stopped() bool {
	return status(t.dbp.pid) == statusStopped
}

func (t *nativeThread) resume() error {
	return t.resumeWithSig(0)
}

func (t *nativeThread) resumeWithSig(sig int) (err error) {
	t.dbp.execPtraceFunc(func() { err = ptraceCont(t.ID, sig) })
	return
}

func (t *nativeThread) singleStep() (err error) {
	t.dbp.execPtraceFunc(func() { err = ptraceStep(t.ID, 0) })
	if err != nil {
		return err
	}
	for {
		th, err := t.dbp.trapWait(t.dbp.pid)
		if err != nil {
			return err
		}
		if th.ID == t.ID {
			break
		}
	}
	return nil
}

func (t *nativeThread) restoreRegisters(savedRegs proc.Registers) error {
	// TODO(jsing): This really should be in registers_openbsd_amd64.go
	sr := savedRegs.(*obsdutil.AMD64Registers)

	var restoreRegistersErr error
	t.dbp.execPtraceFunc(func() { restoreRegistersErr = ptraceSetRegs(t.ID, sr.Regs) })
	if restoreRegistersErr != nil {
		return restoreRegistersErr
	}
	if sr.FPRegSet != nil {
		t.dbp.execPtraceFunc(func() { restoreRegistersErr = ptraceSetFPRegs(t.ID, sr.FPRegSet) })
		if restoreRegistersErr != nil {
			return restoreRegistersErr
		}
	}
	return nil
}

func (t *nativeThread) WriteMemory(addr uint64, data []byte) (written int, err error) {
	if t.dbp.exited {
		return 0, proc.ErrProcessExited{Pid: t.dbp.pid}
	}
	if len(data) == 0 {
		return 0, nil
	}
	t.dbp.execPtraceFunc(func() { written, err = ptraceWriteData(t.ID, uintptr(addr), data) })
	return written, err
}

func (t *nativeThread) ReadMemory(data []byte, addr uint64) (n int, err error) {
	if t.dbp.exited {
		return 0, proc.ErrProcessExited{Pid: t.dbp.pid}
	}
	if len(data) == 0 {
		return 0, nil
	}
	t.dbp.execPtraceFunc(func() { n, err = ptraceReadData(t.ID, uintptr(addr), data) })
	return n, err
}

func (t *nativeThread) withDebugRegisters(f func(*amd64util.DebugRegisters) error) error {
	return proc.ErrHWBreakUnsupported
}

// SoftExc returns true if this thread received a software exception during the last resume.
func (t *nativeThread) SoftExc() bool {
	return false
}
