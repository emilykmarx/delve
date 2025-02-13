package native

import (
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"time"

	"github.com/go-delve/delve/pkg/proc"
	"github.com/go-delve/delve/pkg/proc/linutil"
	sys "golang.org/x/sys/unix"
)

// Process represents all of the information the debugger
// is holding onto regarding the process we are debugging.
type nativeProcess struct {
	bi *proc.BinaryInfo

	pid int // Process Pid

	// Breakpoint table, holds information on breakpoints.
	// Maps instruction address to Breakpoint struct.
	breakpoints proc.BreakpointMap

	// List of threads mapped as such: pid -> *Thread
	threads map[int]*nativeThread

	// Thread used to read and write memory
	memthread *nativeThread

	os           *osProcessDetails
	firstStart   bool
	ptraceThread *ptraceThread
	childProcess bool // this process was launched, not attached to
	followExec   bool // automatically attach to new processes

	// Controlling terminal file descriptor for
	// this process.
	ctty *os.File

	iscgo bool

	exited, detached bool

	// PCs of syscall entry, syscall instruction, and one after syscall instr
	syscallPCs [3]uint64

	pendingWatchpoints []proc.PendingWp
}

// newProcess returns an initialized Process struct. Before returning,
// it will also launch a goroutine in order to handle ptrace(2)
// functions. For more information, see the documentation on
// `handlePtraceFuncs`.
func newProcess(pid int) *nativeProcess {
	dbp := &nativeProcess{
		pid:          pid,
		threads:      make(map[int]*nativeThread),
		breakpoints:  proc.NewBreakpointMap(),
		firstStart:   true,
		os:           new(osProcessDetails),
		ptraceThread: newPtraceThread(),
		bi:           proc.NewBinaryInfo(runtime.GOOS, runtime.GOARCH),
	}
	return dbp
}

// newChildProcess is like newProcess but uses the same ptrace thread as dbp.
func newChildProcess(dbp *nativeProcess, pid int) *nativeProcess {
	return &nativeProcess{
		pid:          pid,
		threads:      make(map[int]*nativeThread),
		breakpoints:  proc.NewBreakpointMap(),
		firstStart:   true,
		os:           new(osProcessDetails),
		ptraceThread: dbp.ptraceThread.acquire(),
		bi:           proc.NewBinaryInfo(runtime.GOOS, runtime.GOARCH),
	}
}

// WaitFor waits for a process as specified by waitFor.
func WaitFor(waitFor *proc.WaitFor) (int, error) {
	t0 := time.Now()
	seen := make(map[int]struct{})
	for (waitFor.Duration == 0) || (time.Since(t0) < waitFor.Duration) {
		pid, err := waitForSearchProcess(waitFor.Name, seen)
		if err != nil {
			return 0, err
		}
		if pid != 0 {
			return pid, nil
		}
		time.Sleep(waitFor.Interval)
	}
	return 0, errors.New("waitfor duration expired")
}

// BinInfo will return the binary info struct associated with this process.
func (dbp *nativeProcess) BinInfo() *proc.BinaryInfo {
	return dbp.bi
}

// StartCallInjection notifies the backend that we are about to inject a function call.
func (dbp *nativeProcess) StartCallInjection() (func(), error) { return func() {}, nil }

// detachWithoutGroup is a helper function to detach from a process which we
// haven't added to a process group yet.
func detachWithoutGroup(dbp *nativeProcess, kill bool) error {
	grp := &processGroup{procs: []*nativeProcess{dbp}}
	return grp.Detach(dbp.pid, kill)
}

// Detach from the process being debugged, optionally killing it.
func (procgrp *processGroup) Detach(pid int, kill bool) (err error) {
	dbp := procgrp.procForPid(pid)
	if ok, _ := dbp.Valid(); !ok {
		return nil
	}
	if kill && dbp.childProcess {
		err := procgrp.kill(dbp)
		if err != nil {
			return err
		}
		return nil
	}
	dbp.execPtraceFunc(func() {
		err = dbp.detach(kill)
		if err != nil {
			return
		}
		if kill {
			err = killProcess(dbp.pid)
		}
	})
	dbp.detached = true
	dbp.postExit()
	return
}

func (procgrp *processGroup) Close() error {
	return nil
}

// Valid returns whether the process is still attached to and
// has not exited.
func (dbp *nativeProcess) Valid() (bool, error) {
	if dbp.detached {
		return false, proc.ErrProcessDetached
	}
	if dbp.exited {
		return false, proc.ErrProcessExited{Pid: dbp.pid}
	}
	return true, nil
}

// ThreadList returns a list of threads in the process.
func (dbp *nativeProcess) ThreadList() []proc.Thread {
	r := make([]proc.Thread, 0, len(dbp.threads))
	for _, v := range dbp.threads {
		r = append(r, v)
	}
	return r
}

// FindThread attempts to find the thread with the specified ID.
func (dbp *nativeProcess) FindThread(threadID int) (proc.Thread, bool) {
	th, ok := dbp.threads[threadID]
	return th, ok
}

// Memory returns the process memory.
func (dbp *nativeProcess) Memory() proc.MemoryReadWriter {
	return dbp.memthread
}

func (dbp *nativeProcess) AddPendingWatchpoint(wp proc.PendingWp) {
	dbp.pendingWatchpoints = append(dbp.pendingWatchpoints, wp)
}

// Breakpoints returns a list of breakpoints currently set.
func (dbp *nativeProcess) Breakpoints() *proc.BreakpointMap {
	return &dbp.breakpoints
}

// RequestManualStop sets the `manualStopRequested` flag and
// sends SIGSTOP to all threads.
func (dbp *nativeProcess) RequestManualStop(cctx *proc.ContinueOnceContext) error {
	if ok, err := dbp.Valid(); !ok {
		return err
	}
	return dbp.requestManualStop()
}

func (dbp *nativeProcess) WriteBreakpoint(bp *proc.Breakpoint) error {
	if bp.WatchType != 0 && bp.WatchImpl == proc.WatchHardware {
		// Hardware watchpoint
		for _, thread := range dbp.threads {
			err := thread.writeHardwareBreakpoint(bp.Addr, bp.WatchType, bp.HWBreakIndex)
			if err != nil {
				return err
			}
		}
		return nil
	} else if bp.WatchType != 0 && bp.WatchImpl == proc.WatchSoftware {
		// Software watchpoint
		return dbp.writeSoftwareWatchpoint(dbp.memthread, bp)
	} else {
		// Software breakpoint
		bp.OriginalData = make([]byte, dbp.bi.Arch.BreakpointSize())
		_, err := dbp.memthread.ReadMemory(bp.OriginalData, bp.Addr)
		if err != nil {
			return err
		}
		return dbp.writeSoftwareBreakpoint(dbp.memthread, bp.Addr)
	}
}

func (dbp *nativeProcess) EraseBreakpoint(bp *proc.Breakpoint) error {
	if bp.WatchType != 0 && bp.WatchImpl == proc.WatchHardware {
		// Hardware watchpoint
		for _, thread := range dbp.threads {
			err := thread.clearHardwareBreakpoint(bp.Addr, bp.WatchType, bp.HWBreakIndex)
			if err != nil {
				return err
			}
		}
		return nil
	} else if bp.WatchType != 0 && bp.WatchImpl == proc.WatchSoftware {
		// Software watchpoint
		return dbp.memthread.clearSoftwareWatchpoint(bp)
	} else {
		// Software breakpoint
		return dbp.memthread.clearSoftwareBreakpoint(bp)
	}
}

type processGroup struct {
	procs     []*nativeProcess
	addTarget proc.AddTargetFunc
}

func (procgrp *processGroup) numValid() int {
	n := 0
	for _, p := range procgrp.procs {
		if ok, _ := p.Valid(); ok {
			n++
		}
	}
	return n
}

func (procgrp *processGroup) procForThread(tid int) *nativeProcess {
	for _, p := range procgrp.procs {
		if p.threads[tid] != nil {
			return p
		}
	}
	return nil
}

func (procgrp *processGroup) procForPid(pid int) *nativeProcess {
	for _, p := range procgrp.procs {
		if p.pid == pid {
			return p
		}
	}
	return nil
}

func (procgrp *processGroup) add(p *nativeProcess, pid int, currentThread proc.Thread, path string, stopReason proc.StopReason, cmdline string) (*proc.Target, error) {
	tgt, err := procgrp.addTarget(p, pid, currentThread, path, stopReason, cmdline)
	if tgt == nil {
		i := len(procgrp.procs)
		procgrp.procs = append(procgrp.procs, p)
		procgrp.detachChild(p)
		if i == len(procgrp.procs)-1 {
			procgrp.procs = procgrp.procs[:i]
		}
	}
	if err != nil {
		return nil, err
	}
	if tgt != nil {
		procgrp.procs = append(procgrp.procs, p)
	}
	return tgt, nil
}

// Print some info on program threads
func ProgramThreads(procgrp *processGroup, msg string) {
	fmt.Printf("Program threads, from %v\n", msg)
	for _, thread := range procgrp.procs[0].ThreadList() {
		loc, _ := thread.Location()
		if loc != nil && loc.Fn != nil && loc.Fn.Name == "main.main" {
			fmt.Printf("Thread %v at line: %v\n", thread.ThreadID(), loc.Line)
			if thread.Breakpoint() != nil && thread.Breakpoint().Breakpoint != nil {
				fmt.Printf("Breakpoint: %v\n", thread.Breakpoint())
			} else {
				fmt.Printf("Nil breakpoint\n")
			}
		}
	}
}

// Handle any breakpoints/watchpoints hit while threads are running during MoveObject
func (procgrp *processGroup) monitorMoveObject(cctx *proc.ContinueOnceContext, dbp *nativeProcess, donech chan error) error {
	fmt.Println("enter monitorMoveObject")
	for {
		// XXX check if any of these functions will use a thread besides trapthread to do ptrace
		// XXX if any hits were non-spurious, return to client
		// XXX test both versions of target (one that would hang, and conn refused)

		select {
		// Two ways to exit this loop:
		// - Get stop signal from MoveObject (trapWait returns SIGSTOP)
		// - Get return value from MoveObject (trapWait would return some thread at a bp/wp, but we should exit)
		// XXX test both cases
		case moveErr := <-donech:
			fmt.Println("donech; exit monitorMoveObject")
			return moveErr
		default:
			// 1. Wait for a thread to hit a bp/wp (or for moveObject to signal that it's done)
			trapthread, err := trapWait(procgrp, -1)
			if err != nil {
				log.Panicf("trapWait error: %v\n", err)
			}
			fmt.Printf("found trapthread %v, status %#x\n", trapthread.ThreadID(), *trapthread.Status)

			if trapthread.stopSignal() == sys.SIGSTOP {
				// From stop() after MoveObject
				fmt.Println("SIGSTOP; exit monitorMoveObject")
				return <-donech
			}

			// 2. Set the stopped thread's breakpoint/watchpoint
			var unused bool
			if err := setThreadBreakpoint(cctx, dbp, trapthread, trapthread, &unused); err != nil {
				log.Panicf("setThreadBreakpoint error for thread %v: %v\n", trapthread.ThreadID(), err)
			}

			fmt.Printf("set bp to %+v\n", trapthread.CurrentBreakpoint.Breakpoint)

			// 3. Step over the breakpoint/watchpoint
			if err := procgrp.stepOverBreakpoint(trapthread, dbp); err != nil {
				if _, ok := err.(SoftwareWatchpointAtBreakpoint); ok {
					// stepped over the bp - now step over the sw wp
					if err := procgrp.stepOverBreakpoint(trapthread, dbp); err != nil {
						log.Panicf("stepOverBreakpoint error for SoftwareWatchpointAtBreakpoint thread %v: %v\n", trapthread.ThreadID(), err)
					}
				} else {
					log.Panicf("stepOverBreakpoint error for thread %v: %v\n", trapthread.ThreadID(), err)
				}
			}

			fmt.Printf("stepped over bp\n")

			// 4. Resume thread
			if err := trapthread.resume(); err != nil && err != sys.ESRCH {
				log.Panicf("resume error for thread %v: %v\n", trapthread.ThreadID(), err)
			}

			fmt.Printf("resumed thread\n")
		}
	}
}

func MoveObjectWithRetries(xv *proc.Variable, dbp *nativeProcess, watchaddrch chan uint64, donech chan error) {
	var watchaddr uint64
	var err error
	i := 0
	// XXX run this a bunch of times - unsure if this combo of n_retries and 5ms sleep will always work
	n_retries := 100
	defer func() {
		// Ensure that main goroutine's trapWait will return
		for _, th := range dbp.threads {
			// loop in case some thread has exited
			if err := th.stop(); err == nil {
				fmt.Printf("sent stop() to thread %v\n", th.ThreadID())
				break
			} else {
				fmt.Printf("failed to send stop() to thread %v\n", th.ThreadID())
			}
		}
	}()

	for ; i < n_retries; i++ {
		watchaddr, err = proc.MoveObject(xv.Addr)
		if err == nil {
			watchaddrch <- watchaddr
			donech <- nil
			return
		} else if strings.Contains(err.Error(), "connection refused") {
			// server thread is at a breakpoint - try again once monitor goroutine has stepped over it
			fmt.Println("conn refused - trying again")
			time.Sleep(5 * time.Millisecond)
		} else {
			donech <- err
			return
		}
	}

	donech <- errors.New("retries exceeded")
}

// Set any watchpoints the client requested during the last stop
// (moving the objects to a tainted page first).
// PERF: no need to call allocator if object isn't on heap (GCTestPointerClass)
// XXX add allocator_http.go to automated suite, and update rest of tests to either pass -nomove,
// or run http server (may also want sleep after set wp so can check it also hits after move)
func (procgrp *processGroup) setPendingWatchpoints(cctx *proc.ContinueOnceContext) {
	for _, dbp := range procgrp.procs {
		if valid, _ := dbp.Valid(); valid {
			for _, wp := range dbp.pendingWatchpoints {
				fmt.Printf("ZZEM setting pending wp: %v\n", wp)
				xv, err := cctx.Target.EvalWatchexpr(wp.Scope, wp.Expr, false)
				if err != nil {
					log.Panicf("eval pending watchpoint %+v: %v", xv, err)
				}

				// 1. Resume all threads to reach HTTP server (may also be needed for pointer updates to avoid hang in GC)
				if err := procgrp.resume(); err != nil {
					if _, ok := err.(SoftwareWatchpointAtBreakpoint); ok {
						// thread was stopped at a breakpoint, now stopped at a software watchpoint
						// XXX think abt if this can happen/what to do
					} else {
						log.Panicf("resume in setPendingWatchpoints: %v", err)
					}
				}

				// 2. Make HTTP request to move object
				watchaddrch := make(chan uint64, 1) // non-blocking sends, since we'll be stuck in trapWait here
				donech := make(chan error, 1)
				go MoveObjectWithRetries(xv, dbp, watchaddrch, donech)

				// 3. Monitor threads until move is done, check result
				if err := procgrp.monitorMoveObject(cctx, dbp, donech); err != nil {
					log.Panicf("MoveObject failed for %+v: %v\n", xv, err)
				}
				watchaddr := <-watchaddrch

				// 4. Stop all threads to set watchpoint (so they can't access the old location in the meantime)
				fmt.Println("about to stop()")
				if _, err := procgrp.stop(cctx, dbp.memthread); err != nil {
					log.Panicf("stop in setPendingWatchpoints: %v", err)
				}

				fmt.Println("about to set wp after successful MoveObject")

				// 4. Set watchpoint on new location
				// XXX set on old location in CreateWatchpoint, un-set here
				_, err = cctx.Target.SetWatchpointNoEval(wp.LogicalID, wp.Scope, wp.Expr, watchaddr, xv.Watchsz,
					proc.WatchRead|proc.WatchWrite, nil, proc.WatchSoftware)
				if err != nil {
					log.Panicf("SetWatchpointNoEval in setPendingWatchpoints: %v\n", err)
				}
			}
			dbp.pendingWatchpoints = nil
		}
	}
}

func (procgrp *processGroup) ContinueOnce(cctx *proc.ContinueOnceContext) (proc.Thread, proc.StopReason, error) {
	if len(procgrp.procs) != 1 && runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		panic("not implemented")
	}
	if procgrp.numValid() == 0 {
		return nil, proc.StopExited, proc.ErrProcessExited{Pid: procgrp.procs[0].pid}
	}

	procgrp.setPendingWatchpoints(cctx)

	for {
		err := procgrp.resume()
		if th, ok := err.(SoftwareWatchpointAtBreakpoint); ok {
			// Return the thread that was stopped at a breakpoint,
			// which is now stopped at a software watchpoint
			return th.trapthread, proc.StopUnknown, nil
		} else if err != nil {
			return nil, proc.StopUnknown, err
		}
		// Redundant? Already cleared bp in resume()
		for _, dbp := range procgrp.procs {
			if valid, _ := dbp.Valid(); valid {
				for _, th := range dbp.threads {
					th.CurrentBreakpoint.Clear()
				}
			}
		}

		if cctx.ResumeChan != nil {
			close(cctx.ResumeChan)
			cctx.ResumeChan = nil
		}

		trapthread, err := trapWait(procgrp, -1)
		if err != nil {
			return nil, proc.StopUnknown, err
		}
		trapthread, err = procgrp.stop(cctx, trapthread)
		if err != nil {
			return nil, proc.StopUnknown, err
		}
		if trapthread != nil {
			dbp := procgrp.procForThread(trapthread.ID)
			dbp.memthread = trapthread

			// refresh memthread for every other process (not interesting for single-process case)
			for _, p2 := range procgrp.procs {
				if p2.exited || p2.detached || p2 == dbp {
					continue
				}
				for _, th := range p2.threads {
					p2.memthread = th
					if th.SoftExc() {
						break
					}
				}
			}

			return trapthread, proc.StopUnknown, nil
		} else {
			// stop() returned nil trapthread => resume()
		}
	}
}

type ptraceSiginfoAmd64 struct {
	signo uint32
	errno uint32
	code  uint32
	_     uint32
	addr  uintptr
	pad   [128]byte // should be enough?
}

const (
	SEGV_ACCERR = 0x2
)

// Assuming thread has just segfaulted, get the faulting address
func (t *nativeThread) faultingAddr() uintptr {
	var err error
	var siginfo ptraceSiginfoAmd64
	t.dbp.execPtraceFunc(func() {
		_, _, err = syscall.Syscall6(syscall.SYS_PTRACE, sys.PTRACE_GETSIGINFO, uintptr(t.ThreadID()), 0, uintptr(unsafe.Pointer(&siginfo)), 0, 0)
	})
	if err != syscall.Errno(0) {
		log.Panicf("PTRACE_GETSIGINFO returned err: %v\n", err.Error())
	}

	if siginfo.signo != uint32(sys.SIGSEGV) || siginfo.code != SEGV_ACCERR || siginfo.errno != 0 {
		pc, _ := t.PC()
		log.Panicf("Siginfo for fault at %#x not as expected: %+v\n", pc, siginfo)
	}

	return siginfo.addr
}

// Memory regions 1 and 2 overlap
func memOverlap(addr1 uint64, sz1 uint64, addr2 uint64, sz2 uint64) bool {
	return addr1 < addr2+sz2 && addr2 < addr1+sz1
}

// Assuming thread just segfaulted (or would in syscall it's about to enter)
// find the software watchpoint for the faulting address (or syscall arg), if any.
// If none (i.e. spurious segfault), return placeholder wp.
func (t *nativeThread) FindSoftwareWatchpoint() *proc.Breakpoint {
	var faultingAddr uint64
	if t.faultingSyscallArg != nil {
		faultingAddr = *t.faultingSyscallArg
	} else {
		faultingAddr = uint64(t.faultingAddr())
	}

	for _, bp := range t.dbp.Breakpoints().M {
		if bp.WatchType != 0 && bp.WatchImpl == proc.WatchSoftware {
			if memOverlap(faultingAddr, 1, bp.Addr, uint64(bp.WatchType.Size())) {
				return bp
			}
		}
	}

	// Not active, so Continue() won't return it to client
	return &proc.Breakpoint{WatchType: proc.WatchWrite, WatchImpl: proc.WatchSoftware,
		Addr: faultingAddr, SpuriousPageFault: true}
}

// FindBreakpoint finds the software breakpoint (not watchpoint) for the given pc.
// Assumes bp instr is the 1B version (as it is in writeSoftwareBreakpoint())
func (dbp *nativeProcess) FindBreakpoint(pc uint64, adjustPC bool) (*proc.Breakpoint, bool) {
	if adjustPC {
		// Check to see if address is past the breakpoint, (i.e. breakpoint was hit).
		if bp, ok := dbp.breakpoints.M[pc-uint64(dbp.bi.Arch.BreakpointSize())]; ok {
			return bp, true
		}
	}
	// Directly use addr to lookup breakpoint.
	if bp, ok := dbp.breakpoints.M[pc]; ok {
		return bp, true
	}
	return nil, false
}

func (dbp *nativeProcess) initializeBasic() (string, error) {
	cmdline, err := initialize(dbp)
	if err != nil {
		return "", err
	}
	if err := dbp.updateThreadList(); err != nil {
		return "", err
	}
	return cmdline, nil
}

// initialize will ensure that all relevant information is loaded
// so the process is ready to be debugged.
func (dbp *nativeProcess) initialize(path string, debugInfoDirs []string) (*proc.TargetGroup, error) {
	cmdline, err := dbp.initializeBasic()
	if err != nil {
		return nil, err
	}
	stopReason := proc.StopLaunched
	if !dbp.childProcess {
		stopReason = proc.StopAttached
	}
	procgrp := &processGroup{}
	grp, addTarget := proc.NewGroup(procgrp, proc.NewTargetGroupConfig{
		DebugInfoDirs: debugInfoDirs,

		// We disable asyncpreempt for the following reasons:
		//  - on Windows asyncpreempt is incompatible with debuggers, see:
		//    https://github.com/golang/go/issues/36494
		//  - on linux/arm64 asyncpreempt can sometimes restart a sequence of
		//    instructions, if the sequence happens to contain a breakpoint it will
		//    look like the breakpoint was hit twice when it was "logically" only
		//    executed once.
		//    See: https://go-review.googlesource.com/c/go/+/208126
		//	- on linux/ppc64le according to @laboger, they had issues in the past
		//	  with gdb once AsyncPreempt was enabled. While implementing the port,
		//	  few tests failed while it was enabled, but cannot be warrantied that
		//	  disabling it fixed the issues.
		//	- on linux/amd64 asyncpreempt causes many spurious sigtraps
		//		when using software watchpoints.
		DisableAsyncPreempt: runtime.GOOS == "windows" || (runtime.GOOS == "linux" && runtime.GOARCH == "arm64") ||
			(runtime.GOOS == "linux" && runtime.GOARCH == "amd64") ||
			(runtime.GOOS == "linux" && runtime.GOARCH == "ppc64le"),

		StopReason: stopReason,
		CanDump:    runtime.GOOS == "linux" || runtime.GOOS == "freebsd" || (runtime.GOOS == "windows" && runtime.GOARCH == "amd64"),
	})
	procgrp.addTarget = addTarget
	tgt, err := procgrp.add(dbp, dbp.pid, dbp.memthread, path, stopReason, cmdline)
	if err != nil {
		return nil, err
	}
	if dbp.bi.Arch.Name == "arm64" || dbp.bi.Arch.Name == "ppc64le" {
		dbp.iscgo = tgt.IsCgo()
	}
	return grp, nil
}

func (pt *ptraceThread) handlePtraceFuncs() {
	// We must ensure here that we are running on the same thread during
	// while invoking the ptrace(2) syscall. This is due to the fact that ptrace(2) expects
	// all commands after PTRACE_ATTACH to come from the same thread.
	runtime.LockOSThread()

	// Leaving the OS thread locked currently leads to segfaults in the
	// Go runtime while running on FreeBSD and OpenBSD:
	//   https://github.com/golang/go/issues/52394
	if runtime.GOOS == "freebsd" || runtime.GOOS == "openbsd" {
		defer runtime.UnlockOSThread()
	}

	for fn := range pt.ptraceChan {
		fn()
		pt.ptraceDoneChan <- nil
	}
	close(pt.ptraceDoneChan)
}

func (dbp *nativeProcess) execPtraceFunc(fn func()) {
	dbp.ptraceThread.ptraceChan <- fn
	<-dbp.ptraceThread.ptraceDoneChan
}

func (dbp *nativeProcess) postExit() {
	dbp.exited = true
	dbp.ptraceThread.release()
	dbp.bi.Close()
	if dbp.ctty != nil {
		dbp.ctty.Close()
	}
	dbp.os.Close()
}

func pageAddr(addr uint64) uint64 {
	return addr &^ (uint64(os.Getpagesize()) - 1)
}

// TODO (minor) handle pages other than R+W - i.e.:
// only remove read perms from existing prot mask, and restore old mask on deleting watchpoint/allowing access
// Also support (or disallow) write/read-write watches
func (thread *nativeThread) toggleMprotect(addr uint64, protect bool) error {
	// 1. Set registers for mprotect syscall: RIP, args, syscall code
	prev_pc, _ := thread.PC()
	prev_regs, err := thread.Registers()
	if err != nil {
		return fmt.Errorf("failed to get regs before mprotect: %v", err.Error())
	}
	regs, err := prev_regs.Copy() // Prevent prev_regs from changing
	if err != nil {
		return fmt.Errorf("failed to copy regs before mprotect: %v", err.Error())
	}
	mprotect_regs := regs.(*linutil.AMD64Registers)

	mprotect_regs.Regs.Rip = thread.dbp.syscallPCs[1]
	mprotect_regs.Regs.Rax = sys.SYS_MPROTECT
	mprotect_regs.Regs.Rdi = pageAddr(addr)
	mprotect_regs.Regs.Rsi = uint64(os.Getpagesize())
	if protect {
		// PERF would be better to allow writes, but doesn't seem to be supported
		// (with PROT_WRITE or PROT_WRITE | PROT_EXEC, page access bits change, but neither reads nor writes fault)
		mprotect_regs.Regs.Rdx = sys.PROT_NONE
	} else {
		mprotect_regs.Regs.Rdx = sys.PROT_READ | sys.PROT_WRITE
	}

	thread.dbp.execPtraceFunc(func() { err = sys.PtraceSetRegs(thread.ID, (*sys.PtraceRegs)(mprotect_regs.Regs)) })
	if err != nil {
		return fmt.Errorf("failed to set regs: %v", err.Error())
	}

	// 2. Execute mprotect syscall
	// TODO (future): See comment on TargetGroup for when group contains > 1 process -
	// if want to support, add a `procgrp` field to dbp? Would also need to update pending wp logic in ContinueOnce
	procgrp := &processGroup{procs: []*nativeProcess{thread.dbp}}
	err = procgrp.singleStep(thread)
	if err != nil {
		if _, exited := err.(proc.ErrProcessExited); exited {
			return err
		}
		return fmt.Errorf("failed to execute syscall instruction for mprotect: %v", err.Error())
	}

	new_regs, err := thread.Registers()
	if err != nil {
		return fmt.Errorf("failed to get regs after mprotect: %v", err.Error())
	}
	mprotect_ret_regs := new_regs.(*linutil.AMD64Registers)
	// Seems like want -1 only for some errnos?
	if mprotect_ret := sys.Errno(-1 * int(mprotect_ret_regs.Regs.Rax)); mprotect_ret != 0 {
		log.Panicf("mprotect for page addr %#x failed: errno %v", pageAddr(addr), mprotect_ret.Error())
	}

	// 3. Restore registers
	if err := thread.RestoreRegisters(prev_regs); err != nil {
		return fmt.Errorf("failed to restore registers after mprotect: %v", err.Error())
	}
	new_pc, _ := thread.PC()
	if prev_pc != new_pc {
		log.Panicf("toggleMprotect failed to restore PC - prev %#x, new %#x\n", prev_pc, new_pc)
	}

	return nil
}

// Whether another software watchpoint (distinguished by ID) exists on the same page as wp
func (dbp *nativeProcess) buddySoftwareWatchpoint(wp *proc.Breakpoint) bool {
	for _, bp := range dbp.Breakpoints().M {
		if bp.WatchType != 0 && bp.WatchImpl == proc.WatchSoftware && bp.LogicalID() != wp.LogicalID() {
			if pageAddr(bp.Addr) == pageAddr(wp.Addr) {
				return true
			}
		}
	}
	return false
}

// mprotect the page containing addr, if needed
func (dbp *nativeProcess) writeSoftwareWatchpoint(thread *nativeThread, wp *proc.Breakpoint) error {
	if !wp.AlwaysToggleMprotect {
		if dbp.buddySoftwareWatchpoint(wp) {
			return nil
		}
	}
	return thread.toggleMprotect(wp.Addr, true)
}

func (dbp *nativeProcess) writeSoftwareBreakpoint(thread *nativeThread, addr uint64) error {
	_, err := thread.WriteMemory(addr, dbp.bi.Arch.BreakpointInstruction())
	return err
}

func openRedirects(stdinPath string, stdoutOR proc.OutputRedirect, stderrOR proc.OutputRedirect, foreground bool) (stdin, stdout, stderr *os.File, closefn func(), err error) {
	toclose := []*os.File{}

	if stdinPath != "" {
		stdin, err = os.Open(stdinPath)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		toclose = append(toclose, stdin)
	} else if foreground {
		stdin = os.Stdin
	}

	create := func(redirect proc.OutputRedirect, dflt *os.File) (f *os.File) {
		if redirect.Path != "" {
			f, err = os.Create(redirect.Path)
			if f != nil {
				toclose = append(toclose, f)
			}

			return f
		} else if redirect.File != nil {
			toclose = append(toclose, redirect.File)

			return redirect.File
		}

		return dflt
	}

	stdout = create(stdoutOR, os.Stdout)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	stderr = create(stderrOR, os.Stderr)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	closefn = func() {
		for _, f := range toclose {
			_ = f.Close()
		}
	}

	return stdin, stdout, stderr, closefn, nil
}

type ptraceThread struct {
	ptraceRefCnt   int
	ptraceChan     chan func()
	ptraceDoneChan chan interface{}
}

func newPtraceThread() *ptraceThread {
	pt := &ptraceThread{
		ptraceChan:     make(chan func()),
		ptraceDoneChan: make(chan interface{}),
		ptraceRefCnt:   1,
	}
	go pt.handlePtraceFuncs()
	return pt
}

func (pt *ptraceThread) acquire() *ptraceThread {
	pt.ptraceRefCnt++
	return pt
}

func (pt *ptraceThread) release() {
	pt.ptraceRefCnt--
	if pt.ptraceRefCnt == 0 {
		close(pt.ptraceChan)
	}
}
