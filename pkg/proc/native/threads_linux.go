package native

import (
	"fmt"
	"log"

	sys "golang.org/x/sys/unix"

	"github.com/go-delve/delve/pkg/proc"
)

type waitStatus sys.WaitStatus

// osSpecificDetails hold Linux specific
// process details.
type osSpecificDetails struct {
	delayedSignal       int
	running             bool
	setbp               bool
	phantomBreakpointPC uint64
}

func (t *nativeThread) stop() (err error) {
	err = sys.Tgkill(t.dbp.pid, t.ID, sys.SIGSTOP)
	if err != nil {
		if err == sys.ESRCH {
			return
		}
		err = fmt.Errorf("stop err %s on thread %d", err, t.ID)
		return
	}
	return
}

// Stopped returns whether the thread is stopped at
// the operating system level.
func (t *nativeThread) Stopped() bool {
	state := status(t.ID, t.dbp.os.comm)
	return state == statusTraceStop || state == statusTraceStopT
}

// Whether thread has exited, without using its status
// (status is only accurate if hasn't changed since last wait)
func (t *nativeThread) Exited() bool {
	err := sys.Tgkill(t.dbp.pid, t.ID, 0)
	if err != nil {
		if err == sys.ESRCH {
			return true
		} else {
			// shouldn't happen - bad ID or perms
			log.Panicf("non-ESRCH error from kill on thread %v with signal 0: %v", t.ID, err)
		}
	}
	return false
}

func (t *nativeThread) resume() error {
	sig := t.os.delayedSignal
	t.os.delayedSignal = 0
	return t.resumeWithSig(sig)
}

func (t *nativeThread) resumeWithSig(sig int) (err error) {
	t.os.running = true
	t.dbp.execPtraceFunc(func() { err = sys.PtraceCont(t.ID, sig) })
	return
}

func (procgrp *processGroup) singleStep(t *nativeThread) (err error) {
	sig := 0
	for {
		t.dbp.execPtraceFunc(func() { err = ptraceSingleStep(t.ID, sig) })
		sig = 0
		if err != nil {
			return err
		}
		wpid, status, err := t.dbp.waitFast(t.ID)
		if err != nil {
			return err
		}
		if (status == nil || status.Exited()) && wpid == t.dbp.pid {
			t.dbp.postExit()
			rs := 0
			if status != nil {
				rs = status.ExitStatus()
			}
			return proc.ErrProcessExited{Pid: t.dbp.pid, Status: rs}
		}
		if wpid == t.ID {
			switch s := status.StopSignal(); s {
			case sys.SIGTRAP:
				// Always expected for singleStep since that's how it's implemented
				return nil
			case sys.SIGSEGV:
				// Trying to step over a software breakpoint at an instr that also faults =>
				// Step over the faulting instr, then return to client if non-spurious.
				pc, _ := t.PC()
				sw_wp := t.FindSoftwareWatchpoint(nil, 1)
				if !sw_wp.SpuriousPageFault {
					// will return this thread to client (propagates to resume() retval - ContinueOnce() will return)
					t.CurrentBreakpoint.Breakpoint = sw_wp
				} else {
					// ignore
				}
				// turn on toggling for duration of singleStep
				sw_wp.AlwaysToggleMprotect = true
				err = t.clearSoftwareWatchpoint(sw_wp)
				if err != nil {
					return err
				}

				defer func() {
					if err := t.dbp.writeSoftwareWatchpoint(t, sw_wp); err != nil {
						log.Panicf("Failed to re-mprotect page after stepping over %#x\n", pc)
					}
					sw_wp.AlwaysToggleMprotect = false
				}()
			case sys.SIGSTOP:
				// delayed SIGSTOP, ignore it
			case sys.SIGILL, sys.SIGBUS, sys.SIGFPE, sys.SIGSTKFLT:
				// propagate signals that can have been caused by the current instruction
				sig = int(s)
			default:
				// delay propagation of all other signals
				t.os.delayedSignal = int(s)
			}
		}
	}
}

func (t *nativeThread) WriteMemory(addr uint64, data []byte) (written int, err error) {
	if ok, err := t.dbp.Valid(); !ok {
		return 0, err
	}
	if len(data) == 0 {
		return
	}
	// ProcessVmWrite can't poke read-only memory like ptrace, so don't
	// even bother for small writes -- likely breakpoints and such.
	if len(data) > sys.SizeofPtr {
		written, _ = processVmWrite(t.ID, uintptr(addr), data)
	}
	if written == 0 {
		t.dbp.execPtraceFunc(func() { written, err = sys.PtracePokeData(t.ID, uintptr(addr), data) })
	}
	return
}

func (t *nativeThread) ReadMemory(data []byte, addr uint64) (n int, err error) {
	if ok, err := t.dbp.Valid(); !ok {
		return 0, err
	}
	if len(data) == 0 {
		return
	}
	n, _ = processVmRead(t.ID, uintptr(addr), data)
	if n == 0 {
		t.dbp.execPtraceFunc(func() { n, err = sys.PtracePeekData(t.ID, uintptr(addr), data) })
	}
	return
}

// SoftExc returns true if this thread received a software exception during the last resume.
func (t *nativeThread) SoftExc() bool {
	return t.os.setbp
}
