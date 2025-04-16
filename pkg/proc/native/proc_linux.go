package native

import (
	"bufio"
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	sys "golang.org/x/sys/unix"

	"github.com/go-delve/delve/pkg/astutil"
	"github.com/go-delve/delve/pkg/logflags"
	"github.com/go-delve/delve/pkg/proc"
	"github.com/go-delve/delve/pkg/proc/internal/ebpf"
	"github.com/go-delve/delve/pkg/proc/linutil"

	isatty "github.com/mattn/go-isatty"
)

// Process statuses
const (
	statusSleeping  = 'S'
	statusRunning   = 'R'
	statusTraceStop = 't'
	statusZombie    = 'Z'

	// Kernel 2.6 has TraceStop as T
	// TODO(derekparker) Since this means something different based on the
	// version of the kernel ('T' is job control stop on modern 3.x+ kernels) we
	// may want to differentiate at some point.
	statusTraceStopT = 'T'

	personalityGetPersonality = 0xffffffff // argument to pass to personality syscall to get the current personality
	_ADDR_NO_RANDOMIZE        = 0x0040000  // ADDR_NO_RANDOMIZE linux constant
)

// osProcessDetails contains Linux specific
// process details.
type osProcessDetails struct {
	comm string

	ebpf *ebpf.EBPFContext
}

func (os *osProcessDetails) Close() {
	if os.ebpf != nil {
		os.ebpf.Close()
	}
}

// Get PCs of Syscall 6 entry, syscall instruction, and one after syscall instr
func (dbp *nativeProcess) getSyscallPCs() [3]uint64 {
	pcs := [3]uint64{}
	syscall_fns := []string{"runtime/internal/syscall.Syscall6", "internal/runtime/syscall.Syscall6"}
	for _, syscall6 := range syscall_fns {
		fns, err := dbp.BinInfo().FindFunction(syscall6)
		if err != nil {
			// try the other fn
			continue
		}
		if pcs[0] > 0 {
			// TODO (minor): also imports other fn - set bp on both
			log.Panicf("imports two versions of Syscall6")
		}

		instrs, err := proc.Disassemble(dbp.Memory(), nil, dbp.Breakpoints(), dbp.BinInfo(), fns[0].Entry, fns[0].End)
		if err != nil {
			log.Panicf("Disassembling %v: %v\n", syscall6, err.Error())
		}

		pcs[0] = instrs[0].Loc.PC
		for i, instr := range instrs {
			instr_text := instr.Text(proc.IntelFlavour, dbp.BinInfo())
			if instr_text == "syscall" {
				pcs[1] = instr.Loc.PC
				pcs[2] = instrs[i+1].Loc.PC
			}
		}
	}
	if pcs[0] == 0 {
		log.Panicf("Failed to find syscall PCs\n")
	}
	return pcs
}

// one-time setup for syscall-related stuff
func (dbp *nativeProcess) setupSyscallHandling() error {
	dbp.syscallPCs = dbp.getSyscallPCs()
	// Break on syscall entry (use cond that always evaluates false so Continue() doesn't return to client)
	false_cond := astutil.Eql(astutil.Int(0), astutil.Int(1))
	target := proc.Target{Process: dbp, Proc: dbp}
	if entry_bp, err := target.SetBreakpoint(proc.SyscallEntryBreakpointID, dbp.syscallPCs[0], proc.UserBreakpoint, false_cond); err != nil {
		return fmt.Errorf("set breakpoint on syscall entry: %v", err)
	} else {
		entry_bp.Logical.Name = proc.SyscallEntryBreakpoint
	}

	return nil
}

// Launch creates and begins debugging a new process. First entry in
// `cmd` is the program to run, and then rest are the arguments
// to be supplied to that process. `wd` is working directory of the program.
// If the DWARF information cannot be found in the binary, Delve will look
// for external debug files in the directories passed in.
func Launch(cmd []string, wd string, flags proc.LaunchFlags,
	debugInfoDirs []string, tty string, stdinPath string, stdoutOR proc.OutputRedirect, stderrOR proc.OutputRedirect,
	targetConfigFiles []string) (*proc.TargetGroup, error) {
	var (
		process *exec.Cmd
		err     error
	)

	foreground := flags&proc.LaunchForeground != 0

	stdin, stdout, stderr, closefn, err := openRedirects(stdinPath, stdoutOR, stderrOR, foreground)
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
			_ = detachWithoutGroup(dbp, true)
		}
	}()
	dbp.execPtraceFunc(func() {
		if flags&proc.LaunchDisableASLR != 0 {
			oldPersonality, _, err := syscall.Syscall(sys.SYS_PERSONALITY, personalityGetPersonality, 0, 0)
			if err == syscall.Errno(0) {
				newPersonality := oldPersonality | _ADDR_NO_RANDOMIZE
				syscall.Syscall(sys.SYS_PERSONALITY, newPersonality, 0, 0)
				defer syscall.Syscall(sys.SYS_PERSONALITY, oldPersonality, 0, 0)
			}
		}

		process = exec.Command(cmd[0])
		process.Args = cmd
		process.Stdin = stdin
		process.Stdout = stdout
		process.Stderr = stderr
		process.SysProcAttr = &syscall.SysProcAttr{
			Ptrace:     true,
			Setpgid:    true,
			Foreground: foreground,
		}
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
	_, _, err = dbp.wait(process.Process.Pid, 0)
	if err != nil {
		return nil, fmt.Errorf("waiting for target execve failed: %s", err)
	}
	tgt, err := dbp.initialize(cmd[0], debugInfoDirs, targetConfigFiles)
	if err != nil {
		return nil, err
	}

	if First_launch {
		Start_time = time.Now()
		First_launch = false
	} else {
		runtime_s := time.Since(Start_time).Seconds()
		// TODO for metrics: Investigate where Launch() is called - ah, from (d *Debugger) Launch()
		// (Currently recorded runtime looks to capture some launch/detach logic).
		// Also assert if any spurious traps, or remove spurious trap counting.
		fmt.Printf("RUNTIME_SEC %v\n", runtime_s)
		fmt.Printf("SEGV_TOTAL %v\t SEGV_TRAPTHREAD %v\n", Sigsegv_total, Sigsegv_trapthread)
		fmt.Printf("SPURIOUS_TRAP_TOTAL %v\t SPURIOUS_TRAP_TRAPTHREAD %v\n", Spurious_sigtrap_total, Spurious_sigtrap_trapthread)
	}
	return tgt, nil
}

// Attach to an existing process with the given PID. Once attached, if
// the DWARF information cannot be found in the binary, Delve will look
// for external debug files in the directories passed in.
func Attach(pid int, waitFor *proc.WaitFor, debugInfoDirs []string) (*proc.TargetGroup, error) {
	if waitFor.Valid() {
		var err error
		pid, err = WaitFor(waitFor)
		if err != nil {
			return nil, err
		}
	}

	dbp := newProcess(pid)

	var err error
	dbp.execPtraceFunc(func() { err = ptraceAttach(dbp.pid) })
	if err != nil {
		return nil, err
	}
	_, _, err = dbp.wait(dbp.pid, 0)
	if err != nil {
		return nil, err
	}

	tgt, err := dbp.initialize(findExecutable("", dbp.pid), debugInfoDirs, nil)
	if err != nil {
		_ = detachWithoutGroup(dbp, false)
		return nil, err
	}

	// ElfUpdateSharedObjects can only be done after we initialize because it
	// needs an initialized BinaryInfo object to work.
	err = linutil.ElfUpdateSharedObjects(dbp)
	if err != nil {
		return nil, err
	}
	return tgt, nil
}

func isProcDir(name string) bool {
	for _, ch := range name {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func waitForSearchProcess(pfx string, seen map[int]struct{}) (int, error) {
	log := logflags.DebuggerLogger()
	des, err := os.ReadDir("/proc")
	if err != nil {
		log.Errorf("error reading proc: %v", err)
		return 0, nil
	}
	for _, de := range des {
		if !de.IsDir() {
			continue
		}
		name := de.Name()
		if !isProcDir(name) {
			continue
		}
		pid, _ := strconv.Atoi(name)
		if _, isseen := seen[pid]; isseen {
			continue
		}
		seen[pid] = struct{}{}
		buf, err := os.ReadFile(filepath.Join("/proc", name, "cmdline"))
		if err != nil {
			// probably we just don't have permissions
			continue
		}
		for i := range buf {
			if buf[i] == 0 {
				buf[i] = ' '
			}
		}
		log.Debugf("waitfor: new process %q", string(buf))
		if strings.HasPrefix(string(buf), pfx) {
			return pid, nil
		}
	}
	return 0, nil
}

func initialize(dbp *nativeProcess) (string, error) {
	comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", dbp.pid))
	if err == nil {
		// removes newline character
		comm = bytes.TrimSuffix(comm, []byte("\n"))
	}

	if comm == nil || len(comm) <= 0 {
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", dbp.pid))
		if err != nil {
			return "", fmt.Errorf("could not read proc stat: %v", err)
		}
		expr := fmt.Sprintf("%d\\s*\\((.*)\\)", dbp.pid)
		rexp, err := regexp.Compile(expr)
		if err != nil {
			return "", fmt.Errorf("regexp compile error: %v", err)
		}
		match := rexp.FindSubmatch(stat)
		if match == nil {
			return "", fmt.Errorf("no match found using regexp '%s' in /proc/%d/stat", expr, dbp.pid)
		}
		comm = match[1]
	}
	dbp.os.comm = strings.ReplaceAll(string(comm), "%", "%%")

	return getCmdLine(dbp.pid), nil
}

func (dbp *nativeProcess) GetBufferedTracepoints() []ebpf.RawUProbeParams {
	if dbp.os.ebpf == nil {
		return nil
	}
	return dbp.os.ebpf.GetBufferedTracepoints()
}

// kill kills the target process.
func (procgrp *processGroup) kill(dbp *nativeProcess) error {
	if ok, _ := dbp.Valid(); !ok {
		return nil
	}
	if !dbp.threads[dbp.pid].Stopped() {
		return errors.New("process must be stopped in order to kill it")
	}
	if err := sys.Kill(-dbp.pid, sys.SIGKILL); err != nil {
		return errors.New("could not deliver signal " + err.Error())
	}
	// wait for other threads first or the thread group leader (dbp.pid) will never exit.
	for threadID := range dbp.threads {
		if threadID != dbp.pid {
			dbp.wait(threadID, 0)
		}
	}
	for {
		wpid, status, err := dbp.wait(dbp.pid, 0)
		if err != nil {
			return err
		}
		if wpid == dbp.pid && status != nil && status.Signaled() && status.Signal() == sys.SIGKILL {
			dbp.postExit()
			return err
		}
	}
}

func (dbp *nativeProcess) requestManualStop() (err error) {
	return sys.Kill(dbp.pid, sys.SIGTRAP)
}

const (
	ptraceOptionsNormal     = syscall.PTRACE_O_TRACECLONE
	ptraceOptionsFollowExec = syscall.PTRACE_O_TRACECLONE | syscall.PTRACE_O_TRACEVFORK | syscall.PTRACE_O_TRACEEXEC
)

// Attach to a newly created thread, and store that thread in our list of
// known threads.
func (dbp *nativeProcess) addThread(tid int, attach bool) (*nativeThread, error) {
	if thread, ok := dbp.threads[tid]; ok {
		return thread, nil
	}

	ptraceOptions := ptraceOptionsNormal
	if dbp.followExec {
		ptraceOptions = ptraceOptionsFollowExec
	}

	var err error
	if attach {
		dbp.execPtraceFunc(func() { err = sys.PtraceAttach(tid) })
		if err != nil && err != sys.EPERM {
			// Do not return err if err == EPERM,
			// we may already be tracing this thread due to
			// PTRACE_O_TRACECLONE. We will surely blow up later
			// if we truly don't have permissions.
			return nil, fmt.Errorf("could not attach to new thread %d %s", tid, err)
		}
		pid, status, err := dbp.waitFast(tid)
		if err != nil {
			return nil, err
		}
		if status.Exited() {
			return nil, fmt.Errorf("thread already exited %d", pid)
		}
	}

	dbp.execPtraceFunc(func() { err = syscall.PtraceSetOptions(tid, ptraceOptions) })
	if err == syscall.ESRCH {
		if _, _, err = dbp.waitFast(tid); err != nil {
			return nil, fmt.Errorf("error while waiting after adding thread: %d %s", tid, err)
		}
		dbp.execPtraceFunc(func() { err = syscall.PtraceSetOptions(tid, ptraceOptions) })
		if err == syscall.ESRCH {
			return nil, err
		}
		if err != nil {
			return nil, fmt.Errorf("could not set options for new traced thread %d %s", tid, err)
		}
	}

	dbp.threads[tid] = &nativeThread{
		ID:  tid,
		dbp: dbp,
		os:  new(osSpecificDetails),
	}
	if dbp.memthread == nil {
		dbp.memthread = dbp.threads[tid]
	}
	for _, bp := range dbp.Breakpoints().M {
		if bp.WatchType != 0 && bp.WatchImpl == proc.WatchHardware {
			err := dbp.threads[tid].writeHardwareBreakpoint(bp.Addr, bp.WatchType, bp.HWBreakIndex)
			if err != nil {
				return nil, err
			}
		}
	}
	return dbp.threads[tid], nil
}

func (dbp *nativeProcess) updateThreadList() error {
	tids, _ := filepath.Glob(fmt.Sprintf("/proc/%d/task/*", dbp.pid))
	for _, tidpath := range tids {
		tidstr := filepath.Base(tidpath)
		tid, err := strconv.Atoi(tidstr)
		if err != nil {
			return err
		}
		if _, err := dbp.addThread(tid, tid != dbp.pid); err != nil {
			return err
		}
	}
	return linutil.ElfUpdateSharedObjects(dbp)
}

func findExecutable(path string, pid int) string {
	if path == "" {
		path = fmt.Sprintf("/proc/%d/exe", pid)
	}
	return path
}

func trapWait(procgrp *processGroup, pid int) (*nativeThread, error) {
	return trapWaitInternal(procgrp, pid, 0)
}

type trapWaitOptions uint8

const (
	trapWaitHalt trapWaitOptions = 1 << iota
	trapWaitNohang
	trapWaitDontCallExitGuard
)

func (t *nativeThread) stopSignal() syscall.Signal {
	if t.Status == nil {
		return -1
	}
	return (*sys.WaitStatus)(t.Status).StopSignal()
}

var (
	Spurious_sigtrap_total      = 0
	Spurious_sigtrap_trapthread = 0
	Sigtrap_info                = map[string]uint64{}
	Sigsegv_total               = 0
	Sigsegv_trapthread          = 0
	First_launch                = true
	Start_time                  = time.Now()
)

const (
	SIGSEGV_STATUS = 0xb7f
	SIGTRAP_STATUS = 0x57f
)

func trapWaitInternal(procgrp *processGroup, pid int, options trapWaitOptions) (*nativeThread, error) {
	var waitdbp *nativeProcess = nil
	if len(procgrp.procs) == 1 {
		// Note that waitdbp is only used to call (*nativeProcess).wait which will
		// behave correctly if waitdbp == nil.
		waitdbp = procgrp.procs[0]
	}

	halt := options&trapWaitHalt != 0
	for {
		wopt := 0
		if options&trapWaitNohang != 0 {
			wopt = sys.WNOHANG
		}
		wpid, status, err := waitdbp.wait(pid, wopt)

		if err != nil {
			return nil, fmt.Errorf("wait err %s %d", err, pid)
		}
		if wpid == 0 {
			if options&trapWaitNohang != 0 {
				return nil, nil
			}
			continue
		}
		dbp := procgrp.procForThread(wpid)
		var th *nativeThread
		if dbp != nil {
			var ok bool
			th, ok = dbp.threads[wpid]
			if ok {
				th.Status = (*waitStatus)(status)
			}
		} else {
			dbp = procgrp.procs[0]
		}
		if status.Exited() {
			if wpid == dbp.pid {
				dbp.postExit()
				if procgrp.numValid() == 0 {
					return nil, proc.ErrProcessExited{Pid: wpid, Status: status.ExitStatus()}
				}
				if halt {
					return nil, nil
				}
				continue
			}
			delete(dbp.threads, wpid)
			continue
		}
		if status.Signaled() {
			// Signaled means the thread was terminated due to a signal.
			if wpid == dbp.pid {
				dbp.postExit()
				if procgrp.numValid() == 0 {
					return nil, proc.ErrProcessExited{Pid: wpid, Status: -int(status.Signal())}
				}
				if halt {
					return nil, nil
				}
				continue
			}
			// does this ever happen?
			delete(dbp.threads, wpid)
			continue
		}
		if status.StopSignal() == sys.SIGTRAP && (status.TrapCause() == sys.PTRACE_EVENT_CLONE || status.TrapCause() == sys.PTRACE_EVENT_VFORK) {
			// A traced thread has cloned a new thread, grab the pid and
			// add it to our list of traced threads.
			// If TrapCause() is sys.PTRACE_EVENT_VFORK this is actually a new
			// process, but treat it as a normal thread until exec happens, so that
			// we can initialize the new process normally.
			var cloned uint
			dbp.execPtraceFunc(func() { cloned, err = sys.PtraceGetEventMsg(wpid) })
			if err != nil {
				if err == sys.ESRCH {
					// thread died while we were adding it
					continue
				}
				return nil, fmt.Errorf("could not get event message: %s", err)
			}
			th, err = dbp.addThread(int(cloned), false)
			if err != nil {
				if err == sys.ESRCH {
					// thread died while we were adding it
					delete(dbp.threads, int(cloned))
					continue
				}
				return nil, err
			}
			if halt {
				th.os.running = false
				dbp.threads[int(wpid)].os.running = false
				return nil, nil
			}
			if err = th.resume(); err != nil {
				if err == sys.ESRCH {
					// thread died while we were adding it
					delete(dbp.threads, th.ID)
					continue
				}
				return nil, fmt.Errorf("could not continue new thread %d %s", cloned, err)
			}
			if err = dbp.threads[int(wpid)].resume(); err != nil {
				if err != sys.ESRCH {
					return nil, fmt.Errorf("could not continue existing thread %d %s", wpid, err)
				}
			}
			continue
		}
		if status.StopSignal() == sys.SIGTRAP && (status.TrapCause() == sys.PTRACE_EVENT_EXEC) {
			// A thread called exec and we now have a new process. Retrieve the
			// thread ID of the exec'ing thread with PtraceGetEventMsg to remove it
			// and create a new nativeProcess object to track the new process.
			var tid uint
			dbp.execPtraceFunc(func() { tid, err = sys.PtraceGetEventMsg(wpid) })
			if err == nil {
				delete(dbp.threads, int(tid))
			}
			dbp = newChildProcess(procgrp.procs[0], wpid)
			dbp.followExec = true
			cmdline, _ := dbp.initializeBasic()
			tgt, err := procgrp.add(dbp, dbp.pid, dbp.memthread, findExecutable("", dbp.pid), proc.StopLaunched, cmdline, nil)
			if err != nil {
				return nil, err
			}
			if halt {
				return nil, nil
			}
			if tgt != nil {
				// If tgt is nil we decided we are not interested in debugging this
				// process, and we have already detached from it.
				err = dbp.threads[dbp.pid].resume()
				if err != nil {
					return nil, err
				}
			}
			//TODO(aarzilli): if we want to give users the ability to stop the target
			//group on exec here is where we should return
			continue
		}
		if th == nil {
			// Sometimes we get an unknown thread, ignore it?
			continue
		}

		// Will set wp if thread segfaulted, whether spuriously or not,
		// so we'll step over it
		if (halt && status.StopSignal() == sys.SIGSTOP) ||
			(status.StopSignal() == sys.SIGTRAP) ||
			(status.StopSignal() == sys.SIGSEGV) {

			th.os.running = false

			if status.StopSignal() == sys.SIGTRAP ||
				status.StopSignal() == sys.SIGSEGV {
				th.os.setbp = true
			}
			return th, nil
		}

		// TODO(dp) alert user about unexpected signals here.
		if halt && !th.os.running {
			// We are trying to stop the process, queue this signal to be delivered
			// to the thread when we resume.
			// Do not do this for threads that were running because we sent them a
			// STOP signal and we need to observe it so we don't mistakenly deliver
			// it later.
			th.os.delayedSignal = int(status.StopSignal())
			th.os.running = false
			return th, nil
		} else if err := th.resumeWithSig(int(status.StopSignal())); err != nil {
			if err != sys.ESRCH {
				return nil, err
			}
			// do the same thing we do if a thread quit
			if wpid == dbp.pid {
				exitStatus := 0
				if procgrp.numValid() == 1 {
					// try to recover the real exit status using waitpid
					for {
						wpid2, status2, err := dbp.wait(-1, sys.WNOHANG)
						if wpid2 <= 0 || err != nil {
							break
						}
						if status2.Exited() {
							exitStatus = status2.ExitStatus()
						}
					}

				}
				dbp.postExit()
				if procgrp.numValid() == 0 {
					return nil, proc.ErrProcessExited{Pid: wpid, Status: exitStatus}
				}
				continue
			}
			delete(dbp.threads, wpid)
		}
	}
}

func status(pid int, comm string) rune {
	f, err := os.Open(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return '\000'
	}
	defer f.Close()
	rd := bufio.NewReader(f)

	var (
		p     int
		state rune
	)

	// The second field of /proc/pid/stat is the name of the task in parentheses.
	// The name of the task is the base name of the executable for this process limited to TASK_COMM_LEN characters
	// Since both parenthesis and spaces can appear inside the name of the task and no escaping happens we need to read the name of the executable first
	// See: include/linux/sched.c:315 and include/linux/sched.c:1510
	_, _ = fmt.Fscanf(rd, "%d ("+comm+")  %c", &p, &state)
	return state
}

// waitFast is like wait but does not handle process-exit correctly
func (dbp *nativeProcess) waitFast(pid int) (int, *sys.WaitStatus, error) {
	var s sys.WaitStatus
	wpid, err := sys.Wait4(pid, &s, sys.WALL, nil)
	return wpid, &s, err
}

func (dbp *nativeProcess) wait(pid, options int) (int, *sys.WaitStatus, error) {
	var s sys.WaitStatus
	if (dbp == nil) || (pid != dbp.pid) || (options != 0) {
		wpid, err := sys.Wait4(pid, &s, sys.WALL|options, nil)
		return wpid, &s, err
	}
	// If we call wait4/waitpid on a thread that is the leader of its group,
	// with options == 0, while ptracing and the thread leader has exited leaving
	// zombies of its own then waitpid hangs forever this is apparently intended
	// behaviour in the linux kernel because it's just so convenient.
	// Therefore we call wait4 in a loop with WNOHANG, sleeping a while between
	// calls and exiting when either wait4 succeeds or we find out that the thread
	// has become a zombie.
	// References:
	// https://sourceware.org/bugzilla/show_bug.cgi?id=12702
	// https://sourceware.org/bugzilla/show_bug.cgi?id=10095
	// https://sourceware.org/bugzilla/attachment.cgi?id=5685
	for {
		wpid, err := sys.Wait4(pid, &s, sys.WNOHANG|sys.WALL|options, nil)
		if err != nil {
			return 0, nil, err
		}
		if wpid != 0 {
			return wpid, &s, err
		}
		if status(pid, dbp.os.comm) == statusZombie {
			return pid, nil, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func exitGuard(dbp *nativeProcess, procgrp *processGroup, err error) error {
	if err != sys.ESRCH {
		return err
	}
	if status(dbp.pid, dbp.os.comm) == statusZombie {
		_, err := trapWaitInternal(procgrp, -1, trapWaitDontCallExitGuard)
		return err
	}

	return err
}

type SoftwareWatchpointAtBreakpoint struct {
	trapthread *nativeThread // thread that hit the wp/bp
}

func (e SoftwareWatchpointAtBreakpoint) Error() string {
	return "non-spurious segfault during step over software breakpoint"
}

func (procgrp *processGroup) stepOverBreakpoint(thread *nativeThread) error {
	prev_bp := thread.CurrentBreakpoint.Breakpoint
	if thread.CurrentBreakpoint.Breakpoint != nil {
		if err := procgrp.stepInstruction(thread); err != nil {
			return err
		}
		if thread.CurrentBreakpoint.Breakpoint != prev_bp {
			fmt.Printf("SoftwareWatchpointAtBreakpoint during resume(); thread %v\n", thread.ThreadID())
			// Non-spurious segfault during step over sw bp
			// (stepInstruction segfaulted and set bp to sw wp)
			// TODO PC is one after the hitting instr, since we just stepped over it - ok to fix by setting thread.PC? Or could fix on client side
			return SoftwareWatchpointAtBreakpoint{thread}
		}

		thread.CurrentBreakpoint.Clear()
	}
	return nil
}

// If th is about to enter a syscall that would fault on one of its args (spuriously or not):
// save the arg and syscall name
func handleSyscallEntry(th *nativeThread) {
	syscall, err := threadStacktrace(th, false, true)
	if err != nil {
		log.Panicf("getting stacktrace in handleSyscallEntry: %v\n", err.Error())
	}
	// PERF for common syscalls we know won't fault, could just resume

	// Syscall6 just moves args from go ABI regs to kernel ABI regs
	raw_regs, err := th.Registers()
	if err != nil {
		log.Panicf("getting regs in handleSyscallEntry: %v\n", err.Error())
	}
	amd_regs := raw_regs.(*linutil.AMD64Registers)
	regs := amd_regs.Regs
	// At syscall entry, regs are the Go ABI, e.g. a1 = Rbx
	arg_regs := []uint64{regs.Rbx, regs.Rcx, regs.Rdi, regs.Rsi, regs.R8, regs.R9}
	for _, arg := range arg_regs {
		// TODO handle multiple faulting args (either bc a single syscall faults on multiple -
		// via one arg overlapping multiple watchpoints (impossible if coalesce them), or multiple args - or bc
		// multiple goroutines on same thread enter a faulting syscall)
		// TODO handle multi-page args
		// TODO handle vector read/write (region won't be contiguous)
		fake_wp := proc.Breakpoint{Addr: arg}
		if th.dbp.buddySoftwareWatchpoint(&fake_wp) {
			// Arg is on same page as a software watchpoint => syscall would fail with "bad address"
			fmt.Printf("ENTER FAULTING SYSCALL %v - arg: %#x\n", syscall, arg)
			threadStacktrace(th, true, false)
			arg_copy := uint64(arg) // was needed at one point - may not be anymore
			th.faultingSyscallArg = &arg_copy
			th.faultingSyscall = &syscall
		}
	}
}

// If this syscall exit corresponds to an entry that would have faulted,
// clear saved arg and name.
func handleSyscallExit(th *nativeThread) {
	fmt.Printf("handleSyscallExit\n")
	syscall, err := threadStacktrace(th, true, true)

	if err != nil {
		log.Panicf("getting stacktrace in handleSyscallExit: %v\n", err.Error())
	}
	if th.faultingSyscall == nil || *th.faultingSyscall != syscall {
		// Exit for a non-faulting syscall (e.g. another thread set the exit bp)
		// TODO unsure how to check if this exit corresponds to a faulting entry -
		// have seen a thread enter multiple syscalls with no exit between.
		// On different goroutines? But getG() can return nil, so may not be able to use goroutine ID.
		// For now, use name of syscall (won't handle this sequence - unsure if possible:
		// "enter faulting syscallX, exit non-faulting syscallX, exit faulting syscallX").
		// Maybe get local vars on exit and see if any would fault.
		if th.faultingSyscall == nil {
			fmt.Printf("th.faultingSyscall nil - won't handle exit\n")
		} else if *th.faultingSyscall != syscall {
			fmt.Printf("*th.faultingSyscall %v != syscall %v - won't handle exit\n", *th.faultingSyscall, syscall)
		}

		return
	}

	fmt.Printf("EXIT FAULTING SYSCALL %v - arg: %#x\n", *th.faultingSyscall, *th.faultingSyscallArg)

	th.faultingSyscallArg = nil
	th.faultingSyscall = nil
}

// Handle any threads that hit a syscall entry/exit bp.
// Should be called after we have set any pending watchpoints just before resume.
// Thus watchpoints are up-to-date to check for syscall faults
// (won't be any new watchpoint requests or object moves before resuming),
// and all threads are stopped (so we can make ptrace calls)
// (May need to update for HTTP server monitoring)
func (procgrp *processGroup) handleSyscallBreakpoints() {
	for _, dbp := range procgrp.procs {
		if valid, _ := dbp.Valid(); !valid {
			continue
		}
		target := proc.Target{Process: dbp, Proc: dbp}
		defer func() {
			// Calling threadStacktrace() refreshes g, which breaks next()
			target.ClearCaches()
		}()

		// 1. Determine which threads are currently in which faulting syscalls
		// (i.e. set thread.faultingSyscall and faultingSyscallArg)
		exited_syscall_args := []uint64{}
		for _, thread := range dbp.threads {
			bp := thread.CurrentBreakpoint.Breakpoint
			if bp != nil {
				if bp.Addr == dbp.syscallPCs[0] {
					// Syscall entry bp
					// TODO if cgo, may not end up in Syscall6 - may need another bp for syscall entry
					// where args are already allocated but still in user space (look for `syscall` instr?)
					handleSyscallEntry(thread)
				} else if bp.Addr == dbp.syscallPCs[2] {
					// Syscall exit bp
					prev_arg := thread.faultingSyscallArg
					handleSyscallExit(thread)
					if thread.faultingSyscallArg == nil && prev_arg != nil {
						// just exited a syscall
						exited_syscall_args = append(exited_syscall_args, *prev_arg)
					}
				}
			}
		}

		// 2. Update things shared across threads accordingly, i.e.
		// page bits and presence of syscall exit breakpoint.

		// 2a. If any thread is in a faulting syscall, set exit breakpoint - else clear it
		if buddy := dbp.buddyFaultingSyscall(nil); buddy != nil {
			fmt.Printf("Thread %v in faulting syscall %v (arg %#x) - setting syscall exit bp (if not exists)\n",
				buddy.ID, *buddy.faultingSyscall, *buddy.faultingSyscallArg)

			// cond always false => will never return bp to client
			false_cond := astutil.Eql(astutil.Int(0), astutil.Int(1))
			exit_bp, err := target.SetBreakpoint(proc.SyscallExitBreakpointID, dbp.syscallPCs[2], proc.UserBreakpoint, false_cond)
			if err != nil {
				if _, exists := err.(proc.BreakpointExistsError); !exists {
					log.Panicf("set syscall exit breakpoint: %v\n", err.Error())
				}
			} else {
				exit_bp.Logical.Name = proc.SyscallExitBreakpoint
			}
		} else {
			err := target.ClearBreakpoint(dbp.syscallPCs[2])
			if err != nil {
				if _, notexists := err.(proc.NoBreakpointError); !notexists {
					log.Panicf("clear syscall exit breakpoint: %v\n", err.Error())
				}
			}
		}

		// 2b. For each page causing a faulting syscall, un-mprotect
		for _, thread := range dbp.threads {
			if thread.faultingSyscallArg != nil {
				faultingAddr := *thread.faultingSyscallArg
				fmt.Printf("Un-mprotecting page causing faulting syscall (if wasn't already): thread %v, syscall %v (arg %#x)\n",
					thread.ID, *thread.faultingSyscall, faultingAddr)
				if err := thread.toggleMprotect(faultingAddr, false); err != nil {
					log.Panicf("un-mprotect in handleSyscallBreakpoints: %v\n", err.Error())
				}
			}
		}

		// 2c. For each page no longer causing a faulting syscall on any thread, re-mprotect
		// (Some thread stopped faulting on it, and no other thread still faulting on it)
		for _, exited_syscall_arg := range exited_syscall_args {
			if dbp.buddyFaultingSyscall(&exited_syscall_arg) == nil {
				// No other thread still faulting on that page
				fmt.Printf("Re-mprotecting page for arg %#x no longer causing faulting syscall\n", exited_syscall_arg)
				if err := dbp.memthread.toggleMprotect(exited_syscall_arg, true); err != nil {
					log.Panicf("re-mprotect in handleSyscallBreakpoints: %v\n", err.Error())
				}
			}
		}
	}
}

func (procgrp *processGroup) resume() error {
	procgrp.handleSyscallBreakpoints()

	// for all threads stopped at a breakpoint, step over it
	for _, dbp := range procgrp.procs {
		if valid, _ := dbp.Valid(); valid {
			for _, thread := range dbp.threads {
				if err := procgrp.stepOverBreakpoint(thread); err != nil {
					return err
				}
			}
		}
	}
	// resume all threads
	for _, dbp := range procgrp.procs {
		if valid, _ := dbp.Valid(); valid {
			for _, thread := range dbp.threads {
				if err := thread.resume(); err != nil && err != sys.ESRCH {
					return err
				}
			}
		}
	}
	return nil
}

// stop stops all running threads and sets breakpoints
func (procgrp *processGroup) stop(cctx *proc.ContinueOnceContext, trapthread *nativeThread) (*nativeThread, error) {
	if procgrp.numValid() == 0 {
		return nil, proc.ErrProcessExited{Pid: procgrp.procs[0].pid}
	}

	for _, dbp := range procgrp.procs {
		if ok, _ := dbp.Valid(); !ok {
			continue
		}
		for _, th := range dbp.threads {
			th.os.setbp = false
		}
	}
	trapthread.os.setbp = true

	// check if any other thread simultaneously received a SIGTRAP or SIGSEGV
	for {
		th, err := trapWaitInternal(procgrp, -1, trapWaitNohang)
		if err != nil {
			return nil, exitGuard(procgrp.procs[0], procgrp, err)
		}
		if th == nil {
			break
		}
	}

	// stop all threads that are still running
	for _, dbp := range procgrp.procs {
		if ok, _ := dbp.Valid(); !ok {
			continue
		}
		for _, th := range dbp.threads {
			if th.os.running {
				if err := th.stop(); err != nil {
					if err == sys.ESRCH {
						// thread exited
						delete(dbp.threads, th.ID)
					} else {
						return nil, exitGuard(dbp, procgrp, err)
					}
				}
			}
		}
	}

	// wait for all threads to stop
	for {
		allstopped := true
		for _, dbp := range procgrp.procs {
			if ok, _ := dbp.Valid(); !ok {
				continue
			}
			for _, th := range dbp.threads {
				if th.os.running {
					allstopped = false
					break
				}
			}
		}
		if allstopped {
			break
		}
		_, err := trapWaitInternal(procgrp, -1, trapWaitHalt)
		if err != nil {
			return nil, err
		}
	}

	switchTrapthread := false

	for _, dbp := range procgrp.procs {
		if ok, _ := dbp.Valid(); !ok {
			continue
		}
		err := stop1(cctx, dbp, trapthread, &switchTrapthread)
		if err != nil {
			return nil, err
		}
	}

	if switchTrapthread {
		trapthreadID := trapthread.ID
		trapthread = nil
		for _, dbp := range procgrp.procs {
			if ok, _ := dbp.Valid(); !ok {
				continue
			}
			for _, th := range dbp.threads {
				if th.os.setbp && th.ThreadID() != trapthreadID {
					return th, nil
				}
			}
		}
	}

	return trapthread, nil
}

func printFaultingSyscall(th *nativeThread) {
	syscall := "nil"
	if th.faultingSyscall != nil {
		syscall = *th.faultingSyscall
	}
	arg := "nil"
	if th.faultingSyscallArg != nil {
		arg = fmt.Sprintf("%#x", *th.faultingSyscallArg)
	}
	goroutine := "nil"
	g, err := proc.GetG(th)
	if err == nil {
		goroutine = fmt.Sprintf("%v", g.ID)
	}

	fmt.Printf("thread %v (goroutine %v), syscall %v, arg %v\n", th.ThreadID(), goroutine, syscall, arg)
}

// If err indicates ESRCH and th hasn't exited, panic.
// (Implies we tried to do a ptrace op on a running thread, which is a bug)
// Else if exited, return true.
func checkESRCH(th *nativeThread, err error) bool {
	if err != nil && strings.Contains(err.Error(), "no such process") {
		// Don't do any ptrace calls here (they'll give ESRCH)
		if th.Exited() {
			return true
		}
		log.Panicf("ESRCH error on non-exited thread %v: %v", th.ThreadID(), err.Error())
	}
	return false
}

// Get stacktrace
// If get_syscall, return the name of the syscall it's in (assumes it's in one)
// Note this has the side effect of possibly refreshing g, which matters if done during certain points in thread lifecycle
func threadStacktrace(th *nativeThread, print bool, get_syscall bool) (string, error) {
	if print {
		printFaultingSyscall(th)
	}
	t := proc.Target{Process: th.dbp}
	stack, err := proc.ThreadStacktrace(&t, th, 50)
	if err != nil {
		fmt.Printf("Failed to get stacktrace: %v\n", err)
		return "", err
	}
	for _, frame := range stack {
		fn := "nil"
		if frame.Call.Fn != nil {
			fn = frame.Call.Fn.Name
		}
		if print {
			fmt.Printf("%#x in %s\n at %s:%d\n", frame.Call.PC, fn, frame.Call.File, frame.Call.Line)
		}
	}
	if get_syscall {
		return stack[3].Call.Fn.Name, nil
	}
	return "", nil
}

func setThreadBreakpoint(cctx *proc.ContinueOnceContext, dbp *nativeProcess, th *nativeThread, trapthread *nativeThread, switchTrapthread *bool) error {
	pc, _ := th.PC()

	if !th.os.setbp && pc != th.os.phantomBreakpointPC {
		// check if this could be a breakpoint hit anyway that the OS hasn't notified us about, yet.
		if _, ok := dbp.FindBreakpoint(pc, dbp.BinInfo().Arch.BreakInstrMovesPC()); ok {
			th.os.phantomBreakpointPC = pc
		}
	}

	if pc != th.os.phantomBreakpointPC {
		th.os.phantomBreakpointPC = 0
	}

	if th.CurrentBreakpoint.Breakpoint == nil && th.os.setbp {
		if err := th.SetCurrentBreakpoint(true); err != nil {
			return err
		}
	}

	// Check spurious sigtrap stuff (only care if th.os.setbp, I think)
	// Here for paranoia - could probably remove
	if th.stopSignal() == syscall.SIGTRAP && th.os.setbp {
		if th.os.phantomBreakpointPC == pc {
			// phantom bp
		} else if bpsize := proc.IsHardcodedBreakpoint(dbp, pc); bpsize > 0 {
			// hardcoded bp
		} else if th.CurrentBreakpoint.Breakpoint != nil {
			// regular bp
		} else {
			// spurious trap
			Spurious_sigtrap_total += 1
			if trapthread.ThreadID() == th.ThreadID() {
				Spurious_sigtrap_trapthread += 1
			}
			Sigtrap_info[fmt.Sprintf("PC %#xXXXX\t th %v", pc>>uint64(16), th.ThreadID())] += 1
		}
	} else if th.stopSignal() == syscall.SIGSEGV && th.os.setbp {
		Sigsegv_total += 1
		if trapthread.ThreadID() == th.ThreadID() {
			Sigsegv_trapthread += 1
		}
	}

	if th.CurrentBreakpoint.Breakpoint == nil && th.os.setbp && (th.Status != nil) && dbp.BinInfo().Arch.BreakInstrMovesPC() {
		manualStop := false
		if th.ThreadID() == trapthread.ThreadID() {
			manualStop = cctx.GetManualStopRequested()
		}

		if !manualStop && th.os.phantomBreakpointPC == pc {
			// Thread received a SIGTRAP or SIGSEGV but we don't have a breakpoint for it and
			// it wasn't sent by a manual stop request. It's either a hardcoded
			// breakpoint or a phantom breakpoint hit (a breakpoint that was hit but
			// we have removed before we could receive its signal). Check if it is a
			// hardcoded breakpoint, otherwise rewind the thread if was SIGTRAP.
			if bpsize := proc.IsHardcodedBreakpoint(dbp, pc); bpsize == 0 {
				// phantom breakpoint hit
				if th.stopSignal() == sys.SIGTRAP {
					_ = th.setPC(pc - uint64(len(dbp.BinInfo().Arch.BreakpointInstruction())))
				}
				th.os.setbp = false
				if trapthread.ThreadID() == th.ThreadID() {
					// Will switch to a different thread for trapthread because we don't
					// want pkg/proc to believe that this thread was stopped by a
					// hardcoded breakpoint.
					// (Unsure if software watchpoints can have phantom hits, but doesn't hurt to
					// switch trapthread, and don't want pkg/proc to check for hardcoded bp)
					fmt.Printf("Phantom breakpoint hit: PC (advanced) %#x, thread %v\n", pc, th.ThreadID())
					*switchTrapthread = true
				}
			}
		}
	}
	return nil
}

func stop1(cctx *proc.ContinueOnceContext, dbp *nativeProcess, trapthread *nativeThread, switchTrapthread *bool) error {
	if err := linutil.ElfUpdateSharedObjects(dbp); err != nil {
		return err
	}

	// set breakpoints on SIGTRAP and SIGSEGV threads
	var err1 error
	for _, th := range dbp.threads {
		err1 = setThreadBreakpoint(cctx, dbp, th, trapthread, switchTrapthread)
	}
	return err1
}

func (procgrp *processGroup) detachChild(dbp *nativeProcess) error {
	return procgrp.Detach(dbp.pid, false)
}

func (dbp *nativeProcess) detach(kill bool) error {
	for threadID := range dbp.threads {
		err := ptraceDetach(threadID, 0)
		if err != nil {
			return err
		}
	}
	if kill {
		return nil
	}
	// For some reason the process will sometimes enter stopped state after a
	// detach, this doesn't happen immediately either.
	// We have to wait a bit here, then check if the main thread is stopped and
	// SIGCONT it if it is.
	time.Sleep(50 * time.Millisecond)
	if s := status(dbp.pid, dbp.os.comm); s == 'T' {
		_ = sys.Kill(dbp.pid, sys.SIGCONT)
	}
	return nil
}

// EntryPoint will return the process entry point address, useful for
// debugging PIEs.
func (dbp *nativeProcess) EntryPoint() (uint64, error) {
	auxvbuf, err := os.ReadFile(fmt.Sprintf("/proc/%d/auxv", dbp.pid))
	if err != nil {
		return 0, fmt.Errorf("could not read auxiliary vector: %v", err)
	}

	return linutil.EntryPointFromAuxv(auxvbuf, dbp.bi.Arch.PtrSize()), nil
}

func (dbp *nativeProcess) SetUProbe(fnName string, goidOffset int64, args []ebpf.UProbeArgMap) error {
	// Lazily load and initialize the BPF program upon request to set a uprobe.
	if dbp.os.ebpf == nil {
		var err error
		dbp.os.ebpf, err = ebpf.LoadEBPFTracingProgram(dbp.bi.Images[0].Path)
		if err != nil {
			return err
		}
	}

	// We only allow up to 12 args for a BPF probe.
	// 6 inputs + 6 outputs.
	// Return early if we have more.
	if len(args) > 12 {
		return errors.New("too many arguments in traced function, max is 12 input+return")
	}

	fns := dbp.bi.LookupFunc()[fnName]
	if len(fns) != 1 {
		return &proc.ErrFunctionNotFound{FuncName: fnName}
	}
	fn := fns[0]

	offset, err := dbp.BinInfo().GStructOffset(dbp.Memory())
	if err != nil {
		return err
	}
	key := fn.Entry
	err = dbp.os.ebpf.UpdateArgMap(key, goidOffset, args, offset, false)
	if err != nil {
		return err
	}

	debugname := dbp.bi.Images[0].Path

	// First attach a uprobe at all return addresses. We do this instead of using a uretprobe
	// for two reasons:
	// 1. uretprobes do not play well with Go
	// 2. uretprobes seem to not restore the function return addr on the stack when removed, destroying any
	//    kind of workaround we could come up with.
	// TODO(derekparker): this whole thing could likely be optimized a bit.
	img := dbp.BinInfo().PCToImage(fn.Entry)
	f, err := elf.Open(img.Path)
	if err != nil {
		return fmt.Errorf("could not open elf file to resolve symbol offset: %w", err)
	}

	var regs proc.Registers
	mem := dbp.Memory()
	regs, _ = dbp.memthread.Registers()
	instructions, err := proc.Disassemble(mem, regs, &proc.BreakpointMap{}, dbp.BinInfo(), fn.Entry, fn.End)
	if err != nil {
		return err
	}

	var addrs []uint64
	for _, instruction := range instructions {
		if instruction.IsRet() {
			addrs = append(addrs, instruction.Loc.PC)
		}
	}
	addrs = append(addrs, proc.FindDeferReturnCalls(instructions)...)
	for _, addr := range addrs {
		err := dbp.os.ebpf.UpdateArgMap(addr, goidOffset, args, offset, true)
		if err != nil {
			return err
		}
		off, err := ebpf.AddressToOffset(f, addr)
		if err != nil {
			return err
		}
		err = dbp.os.ebpf.AttachUprobe(dbp.pid, debugname, off)
		if err != nil {
			return err
		}
	}

	off, err := ebpf.AddressToOffset(f, fn.Entry)
	if err != nil {
		return err
	}

	return dbp.os.ebpf.AttachUprobe(dbp.pid, debugname, off)
}

// FollowExec enables (or disables) follow exec mode
func (dbp *nativeProcess) FollowExec(v bool) error {
	dbp.followExec = v
	ptraceOptions := ptraceOptionsNormal
	if dbp.followExec {
		ptraceOptions = ptraceOptionsFollowExec
	}
	var err error
	dbp.execPtraceFunc(func() {
		for tid := range dbp.threads {
			err = syscall.PtraceSetOptions(tid, ptraceOptions)
			if err != nil {
				return
			}
		}
	})
	return err
}

func killProcess(pid int) error {
	return sys.Kill(pid, sys.SIGINT)
}

func getCmdLine(pid int) string {
	buf, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	args := strings.SplitN(string(buf), "\x00", -1)
	for i := range args {
		if strings.Contains(args[i], " ") {
			args[i] = strconv.Quote(args[i])
		}
	}
	if len(args) > 0 && args[len(args)-1] == "" {
		args = args[:len(args)-1]
	}
	return strings.Join(args, " ")
}
