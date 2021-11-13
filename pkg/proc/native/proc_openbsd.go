package native

// #cgo LDFLAGS: -lkvm
//
// #include <sys/types.h>
// #include <sys/ptrace.h>
// #include <sys/sysctl.h>
//
// #include <elf.h>
// #include <kvm.h>
// #include <limits.h>
// #include <stdlib.h>
//
import "C"
import (
	"errors"
	"fmt"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"unsafe"

	sys "golang.org/x/sys/unix"

	"github.com/go-delve/delve/pkg/proc"
	"github.com/go-delve/delve/pkg/proc/internal/ebpf"

	isatty "github.com/mattn/go-isatty"
)

// Process statuses
const (
	statusIdle     = 1
	statusRunning  = 2
	statusSleeping = 3
	statusStopped  = 4
	statusZombie   = 5
	statusWaiting  = 6
	statusLocked   = 7
)

// osProcessDetails contains OpenBSD specific process details.
type osProcessDetails struct {
	comm string
	tid  int
}

func (os *osProcessDetails) Close() {}

// Launch creates and begins debugging a new process. First entry in
// `cmd` is the program to run, and then rest are the arguments
// to be supplied to that process. `wd` is working directory of the program.
// If the DWARF information cannot be found in the binary, Delve will look
// for external debug files in the directories passed in.
func Launch(cmd []string, wd string, flags proc.LaunchFlags, debugInfoDirs []string, tty string, redirects [3]string) (*proc.Target, error) {
	var (
		process *exec.Cmd
		err     error
	)

	foreground := flags&proc.LaunchForeground != 0

	stdin, stdout, stderr, closefn, err := openRedirects(redirects, foreground)
	if err != nil {
		return nil, err
	}

	if stdin == nil || !isatty.IsTerminal(stdin.Fd()) {
		// exec.(*Process).Start will fail if we try to send a process to
		// foreground but we are not attached to a terminal.
		foreground = false
	}

	dbp := newProcess(0)
	defer func() {
		if err != nil && dbp.pid != 0 {
			_ = dbp.Detach(true)
		}
	}()
	dbp.execPtraceFunc(func() {
		process = exec.Command(cmd[0])
		process.Args = cmd
		process.Stdin = stdin
		process.Stdout = stdout
		process.Stderr = stderr
		process.SysProcAttr = &syscall.SysProcAttr{Ptrace: true, Setpgid: true, Foreground: foreground}
		process.Env = proc.DisableAsyncPreemptEnv()
		if foreground {
			signal.Ignore(syscall.SIGTTOU, syscall.SIGTTIN)
		}
		if tty != "" {
			dbp.ctty, err = attachProcessToTTY(process, tty)
			if err != nil {
				return
			}
		}
		if wd != "" {
			process.Dir = wd
		}
		err = process.Start()
	})
	closefn()
	if err != nil {
		return nil, err
	}
	dbp.pid = process.Process.Pid
	dbp.childProcess = true
	if _, _, err := dbp.wait(process.Process.Pid, 0); err != nil {
		return nil, fmt.Errorf("waiting for target execve failed: %s", err)
	}
	tgt, err := dbp.initialize(cmd[0], debugInfoDirs)
	if err != nil {
		return nil, err
	}
	return tgt, nil
}

// Attach to an existing process with the given PID. Once attached, if
// the DWARF information cannot be found in the binary, Delve will look
// for external debug files in the directories passed in.
func Attach(pid int, debugInfoDirs []string) (*proc.Target, error) {
	dbp := newProcess(pid)

	var err error
	dbp.execPtraceFunc(func() { err = ptraceAttach(dbp.pid) })
	if err != nil {
		return nil, err
	}
	if _, _, err := dbp.wait(dbp.pid, 0); err != nil {
		return nil, err
	}

	tgt, err := dbp.initialize(findExecutable("", dbp.pid), debugInfoDirs)
	if err != nil {
		dbp.Detach(false)
		return nil, err
	}
	return tgt, nil
}

func initialize(dbp *nativeProcess) error {
	comm, err := commandName(dbp.pid)
	if err != nil {
		return err
	}
	dbp.os.comm = strings.Replace(comm, "%", "%%", -1)
	return nil
}

// kill kills the target process.
func (dbp *nativeProcess) kill() (err error) {
	if dbp.exited {
		return nil
	}
	dbp.execPtraceFunc(func() { err = ptraceCont(dbp.pid, int(sys.SIGKILL)) })
	if err != nil {
		return err
	}
	if _, _, err = dbp.wait(dbp.pid, 0); err != nil {
		return err
	}
	dbp.postExit()
	return nil
}

func (dbp *nativeProcess) requestManualStop() (err error) {
	return sys.Kill(dbp.pid, sys.SIGTRAP)
}

// Attach to a newly created thread, and store that thread in our list of
// known threads.
func (dbp *nativeProcess) addThread(tid int, attach bool) (*nativeThread, error) {
	if thread, ok := dbp.threads[tid]; ok {
		return thread, nil
	}

	thread := &nativeThread{
		ID:  tid,
		dbp: dbp,
		os:  new(osSpecificDetails),
	}
	dbp.threads[tid] = thread

	if dbp.memthread == nil {
		dbp.memthread = thread
	}

	return thread, nil
}

func (dbp *nativeProcess) updateThreadList() error {
	var tids []int32
	var err error
	dbp.execPtraceFunc(func() { tids, err = ptraceThreadIDs(dbp.pid) })
	if err != nil {
		return err
	}
	for _, tid := range tids {
		if _, err := dbp.addThread(int(tid), false); err != nil {
			return err
		}
	}
	dbp.os.tid = int(tids[0])
	return nil
}

func findExecutable(path string, pid int) string {
	// Not possible on OpenBSD.
	return path
}

func (dbp *nativeProcess) trapWait(pid int) (*nativeThread, error) {
	return dbp.trapWaitInternal(pid, false)
}

func (dbp *nativeProcess) trapWaitInternal(pid int, halt bool) (*nativeThread, error) {
	for {
		wpid, status, err := dbp.wait(pid, 0)
		if err != nil {
			return nil, fmt.Errorf("wait err %s %d", err, pid)
		}
		if status.Killed() {
			// "Killed" status may arrive as a result of a Process.Kill() of some other process in
			// the system performed by the same tracer (e.g. in the previous test)
			continue
		}
		if status.Exited() {
			dbp.postExit()
			return nil, proc.ErrProcessExited{Pid: wpid, Status: status.ExitStatus()}
		}

		var pid, tid int
		dbp.execPtraceFunc(func() { _, pid, tid, err = ptraceProcessState(wpid) })
		if err != nil {
			return nil, fmt.Errorf("ptraceProcessState failed for pid %d: %v", pid, err)
		}

		// TODO(jsing): Is there a way to be told about new threads?
		dbp.updateThreadList()

		th, ok := dbp.threads[tid]
		if ok {
			th.Status = (*waitStatus)(status)
		}
		if th == nil {
			continue
		}

		if (halt && status.StopSignal() == sys.SIGSTOP) || (status.StopSignal() == sys.SIGTRAP) {
			return th, nil
		}

		// TODO(dp) alert user about unexpected signals here.
		if err := th.resumeWithSig(int(status.StopSignal())); err != nil {
			if err == sys.ESRCH {
				return nil, proc.ErrProcessExited{Pid: dbp.pid}
			}
			return nil, err
		}
	}
}

// waitFast is like wait but does not handle process-exit correctly
func (dbp *nativeProcess) waitFast(pid int) (int, *sys.WaitStatus, error) {
	var s sys.WaitStatus
	wpid, err := sys.Wait4(pid, &s, 0, nil)
	return wpid, &s, err
}

func (dbp *nativeProcess) wait(pid, options int) (int, *sys.WaitStatus, error) {
	var s sys.WaitStatus
	wpid, err := sys.Wait4(pid, &s, options, nil)
	return wpid, &s, err
}

func (dbp *nativeProcess) exitGuard(err error) error {
	if err != sys.ESRCH {
		return err
	}
	if status(dbp.pid) == statusZombie {
		_, err := dbp.trapWaitInternal(-1, false)
		return err
	}

	return err
}

func (dbp *nativeProcess) resume() error {
	// all threads stopped over a breakpoint are made to step over it
	for _, thread := range dbp.threads {
		if thread.CurrentBreakpoint.Breakpoint != nil {
			if err := thread.StepInstruction(); err != nil {
				return err
			}
			thread.CurrentBreakpoint.Clear()
		}
	}
	// all threads are resumed
	var err error
	dbp.execPtraceFunc(func() { err = ptraceCont(dbp.pid, 0) })
	return err
}

// stop stops all running threads and sets breakpoints
func (dbp *nativeProcess) stop(cctx *proc.ContinueOnceContext, trapthread *nativeThread) (*nativeThread, error) {
	if dbp.exited {
		return nil, proc.ErrProcessExited{Pid: dbp.pid}
	}
	// set breakpoints on all threads
	for _, th := range dbp.threads {
		if th.CurrentBreakpoint.Breakpoint == nil {
			if err := th.SetCurrentBreakpoint(true); err != nil {
				return nil, err
			}
		}
	}
	return trapthread, nil
}

func (dbp *nativeProcess) detach(kill bool) error {
	return ptraceDetach(dbp.pid)
}

const (
	auxNULL  = 0
	auxEntry = 9
)

type auxInfo struct {
	id int32
	v  uint64
}

// EntryPoint returns the process entry point address, useful for debugging PIEs.
func (dbp *nativeProcess) EntryPoint() (uint64, error) {
	var (
		err error
		n   int
	)
	data := make([]byte, 1024)
	dbp.execPtraceFunc(func() { n, err = ptraceReadAuxInfo(dbp.pid, data) })
	if err != nil {
		return 0, err
	}
	var ai *auxInfo
	for i := 0; i < n; i += int(unsafe.Sizeof(*ai)) {
		ai = (*auxInfo)(unsafe.Pointer(&data[i]))
		if ai.id == auxEntry {
			return ai.v, nil
		}
		if ai.id == auxNULL {
			break
		}
	}
	return 0, nil
}

func (dbp *nativeProcess) SupportsBPF() bool {
	return false
}

func (dbp *nativeProcess) SetUProbe(fnName string, goidOffset int64, args []ebpf.UProbeArgMap) error {
	panic("not implemented")
}

func (dbp *nativeProcess) GetBufferedTracepoints() []ebpf.RawUProbeParams {
	panic("not implemented")
}

func kvmGetProc(pid int) (*C.struct_kinfo_proc, error) {
	var errbuf [C._POSIX2_LINE_MAX]C.char
	flags := uint32(C.KVM_NO_FILES)
	kd := C.kvm_openfiles(nil, nil, nil, C.int(flags), (*C.char)(unsafe.Pointer(&errbuf[0])))
	if kd == nil {
		return nil, fmt.Errorf("kvm_openfiles failed: %v", C.GoStringN(&errbuf[0], C.int(unsafe.Sizeof(errbuf))))
	}

	var kinfo C.struct_kinfo_proc
	var cnt int
	kp := C.kvm_getprocs(kd, C.KERN_PROC_PID, C.int(pid), C.ulong(unsafe.Sizeof(kinfo)), (*C.int)(unsafe.Pointer(&cnt)))
	if kp == nil {
		return nil, fmt.Errorf("kvm_getprocs failed: %v", C.GoString(C.kvm_geterr(kd)))
	}
	if cnt == 0 {
		return nil, errors.New("process not found")
	}
	if cnt != 1 {
		return nil, fmt.Errorf("kvm_getprocs returned %d processes", cnt)
	}
	kinfo = *kp

	C.kvm_close(kd)

	return &kinfo, nil
}

// commandName returns the original command name for the given process.
func commandName(pid int) (string, error) {
	ki, err := kvmGetProc(pid)
	if err != nil {
		return "", err
	}
	return C.GoStringN(&ki.p_comm[0], C.int(unsafe.Sizeof(ki.p_comm))), nil
}

// status returns the status code of the given process.
func status(pid int) int8 {
	ki, err := kvmGetProc(pid)
	if err != nil {
		return -1 // XXX
	}
	return int8(ki.p_stat)
}

func killProcess(pid int) error {
	return sys.Kill(pid, sys.SIGINT)
}
