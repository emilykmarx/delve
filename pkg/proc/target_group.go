package proc

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/go-delve/delve/pkg/logflags"
)

// TODO enable followExec (and check if works - may have broken it in places, e.g. see comment in toggleMprotect) -
// needed to allow target to fork/exec, and to scan its child which may also access module's config

// TargetGroup represents a group of target processes being debugged that
// will be resumed and stopped simultaneously.
// New targets are automatically added to the group if exec catching is
// enabled and the backend supports it, otherwise the group will always
// contain a single target process.
type TargetGroup struct {
	procgrp ProcessGroup

	targets           []*Target
	Selected          *Target
	followExecEnabled bool
	followExecRegex   *regexp.Regexp

	RecordingManipulation
	recman RecordingManipulationInternal

	// StopReason describes the reason why the selected target process is stopped.
	// A process could be stopped for multiple simultaneous reasons, in which
	// case only one will be reported.
	StopReason StopReason

	// KeepSteppingBreakpoints determines whether certain stop reasons (e.g. manual halts)
	// will keep the stepping breakpoints instead of clearing them.
	KeepSteppingBreakpoints KeepSteppingBreakpoints

	LogicalBreakpoints map[int]*LogicalBreakpoint

	cctx    *ContinueOnceContext
	cfg     NewTargetGroupConfig
	CanDump bool
}

// NewTargetGroupConfig contains the configuration for a new TargetGroup object,
type NewTargetGroupConfig struct {
	DebugInfoDirs       []string   // Directories to search for split debug info
	DisableAsyncPreempt bool       // Go 1.14 asynchronous preemption should be disabled
	StopReason          StopReason // Initial stop reason
	CanDump             bool       // Can create core dumps (must implement ProcessInternal.MemoryMap)
}

type AddTargetFunc func(ProcessInternal, int, Thread, string, StopReason, string, []string) (*Target, error)

// NewGroup creates a TargetGroup containing the specified Target.
func NewGroup(procgrp ProcessGroup, cfg NewTargetGroupConfig) (*TargetGroup, AddTargetFunc) {
	grp := &TargetGroup{
		procgrp:            procgrp,
		cctx:               &ContinueOnceContext{},
		LogicalBreakpoints: make(map[int]*LogicalBreakpoint),
		StopReason:         cfg.StopReason,
		cfg:                cfg,
		CanDump:            cfg.CanDump,
	}
	return grp, grp.addTarget
}

// Restart copies breakpoints and follow exec status from oldgrp into grp.
// Breakpoints that can not be set will be discarded, if discard is not nil
// it will be called for each discarded breakpoint.
func Restart(grp, oldgrp *TargetGroup, discard func(*LogicalBreakpoint, error)) {
	for _, bp := range oldgrp.LogicalBreakpoints {
		if _, ok := grp.LogicalBreakpoints[bp.LogicalID]; ok {
			continue
		}
		grp.LogicalBreakpoints[bp.LogicalID] = bp
		bp.TotalHitCount = 0
		bp.HitCount = make(map[int64]uint64)
		bp.Set.PidAddrs = nil // breakpoints set through a list of addresses can not be restored after a restart
		if bp.Enabled {
			err := grp.EnableBreakpoint(bp)
			if err != nil {
				if discard != nil {
					discard(bp, err)
				}
				delete(grp.LogicalBreakpoints, bp.LogicalID)
			}
		}
	}
	if oldgrp.followExecEnabled {
		rgx := ""
		if oldgrp.followExecRegex != nil {
			rgx = oldgrp.followExecRegex.String()
		}
		grp.FollowExec(true, rgx)
	}
}

func (grp *TargetGroup) addTarget(p ProcessInternal, pid int, currentThread Thread, path string, stopReason StopReason, cmdline string, configFiles []string) (*Target, error) {
	logger := logflags.DebuggerLogger()
	if len(grp.targets) > 0 {
		if !grp.followExecEnabled {
			logger.Debugf("Detaching from child target (follow-exec disabled) %d %q", pid, cmdline)
			return nil, nil
		}
		if grp.followExecRegex != nil && !grp.followExecRegex.MatchString(cmdline) {
			logger.Debugf("Detaching from child target (follow-exec regex not matched) %d %q", pid, cmdline)
			return nil, nil
		}
	}
	t, err := grp.newTarget(p, pid, currentThread, path, cmdline, configFiles)
	if err != nil {
		return nil, err
	}
	t.StopReason = stopReason
	logger.Debugf("Adding target %d %q", t.Pid(), t.CmdLine)
	if t.partOfGroup {
		panic("internal error: target is already part of group")
	}
	t.partOfGroup = true
	if grp.RecordingManipulation == nil {
		grp.RecordingManipulation = t.recman
		grp.recman = t.recman
	}
	if grp.Selected == nil {
		grp.Selected = t
	}
	t.Breakpoints().Logical = grp.LogicalBreakpoints
	for _, lbp := range grp.LogicalBreakpoints {
		if lbp.LogicalID < 0 {
			continue
		}
		err := enableBreakpointOnTarget(t, lbp)
		if err != nil {
			logger.Debugf("could not enable breakpoint %d on new target %d: %v", lbp.LogicalID, t.Pid(), err)
		} else {
			logger.Debugf("breakpoint %d enabled on new target %d: %v", lbp.LogicalID, t.Pid(), err)
		}
	}
	grp.targets = append(grp.targets, t)
	return t, nil
}

// Targets returns a slice of all targets in the group, including the
// ones that are no longer valid.
func (grp *TargetGroup) Targets() []*Target {
	return grp.targets
}

// Valid returns true if any target in the target group is valid.
func (grp *TargetGroup) Valid() (bool, error) {
	var err0 error
	for _, t := range grp.targets {
		ok, err := t.Valid()
		if ok {
			return true, nil
		}
		if err0 == nil {
			err0 = err
		}
	}
	return false, err0
}

func (grp *TargetGroup) numValid() int {
	r := 0
	for _, t := range grp.targets {
		ok, _ := t.Valid()
		if ok {
			r++
		}
	}
	return r
}

// Detach detaches all targets in the group.
func (grp *TargetGroup) Detach(kill bool) error {
	var errs []string
	for i := len(grp.targets) - 1; i >= 0; i-- {
		t := grp.targets[i]
		isvalid, _ := t.Valid()
		if !isvalid {
			continue
		}
		err := grp.detachTarget(t, kill)
		if err != nil {
			errs = append(errs, fmt.Sprintf("could not detach process %d: %v", t.Pid(), err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "\n"))
	}
	return grp.procgrp.Close()
}

// detachTarget will detach the target from the underlying process.
// This means the debugger will no longer receive events from the process
// we were previously debugging.
// If kill is true then the process will be killed when we detach.
func (grp *TargetGroup) detachTarget(t *Target, kill bool) error {
	if !kill {
		if t.asyncPreemptChanged {
			setAsyncPreemptOff(t, t.asyncPreemptOff)
		}
		for _, bp := range t.Breakpoints().M {
			if bp != nil {
				err := t.ClearBreakpoint(bp.Addr)
				if err != nil {
					return err
				}
			}
		}
	}
	t.StopReason = StopUnknown
	return grp.procgrp.Detach(t.Pid(), kill)
}

// HasSteppingBreakpoints returns true if any of the targets has stepping breakpoints set.
func (grp *TargetGroup) HasSteppingBreakpoints() bool {
	for _, t := range grp.targets {
		if t.Breakpoints().HasSteppingBreakpoints() {
			return true
		}
	}
	return false
}

// ClearSteppingBreakpoints removes all stepping breakpoints.
func (grp *TargetGroup) ClearSteppingBreakpoints() error {
	for _, t := range grp.targets {
		if t.Breakpoints().HasSteppingBreakpoints() {
			return t.ClearSteppingBreakpoints()
		}
	}
	return nil
}

// ThreadList returns a list of all threads in all target processes.
func (grp *TargetGroup) ThreadList() []Thread {
	r := []Thread{}
	for _, t := range grp.targets {
		r = append(r, t.ThreadList()...)
	}
	return r
}

// TargetForThread returns the target containing the given thread.
func (grp *TargetGroup) TargetForThread(tid int) *Target {
	for _, t := range grp.targets {
		if _, ok := t.FindThread(tid); ok {
			return t
		}
	}
	return nil
}

// EnableBreakpoint re-enables a disabled logical breakpoint.
func (grp *TargetGroup) EnableBreakpoint(lbp *LogicalBreakpoint) error {
	var err0, errNotFound, errExists error
	didSet := false
targetLoop:
	for _, p := range grp.targets {
		err := enableBreakpointOnTarget(p, lbp)

		switch err.(type) {
		case nil:
			didSet = true
		case *ErrFunctionNotFound, *ErrCouldNotFindLine:
			errNotFound = err
		case BreakpointExistsError:
			errExists = err
		default:
			err0 = err
			break targetLoop
		}
	}
	if errNotFound != nil && !didSet {
		return errNotFound
	}
	if errExists != nil && !didSet {
		return errExists
	}
	if !didSet {
		if _, err := grp.Valid(); err != nil {
			return err
		}
	}
	if err0 != nil {
		it := ValidTargets{Group: grp}
		for it.Next() {
			for _, bp := range it.Breakpoints().M {
				if bp.LogicalID() == lbp.LogicalID {
					if err1 := it.ClearBreakpoint(bp.Addr); err1 != nil {
						return fmt.Errorf("error while creating breakpoint: %v, additionally the breakpoint could not be properly rolled back: %v", err0, err1)
					}
				}
			}
		}
		return err0
	}
	lbp.Enabled = true
	return nil
}

func enableBreakpointOnTarget(p *Target, lbp *LogicalBreakpoint) error {
	var err error
	var addrs []uint64
	switch {
	case lbp.Set.File != "":
		addrs, err = FindFileLocation(p, lbp.Set.File, lbp.Set.Line)
	case lbp.Set.FunctionName != "":
		addrs, err = FindFunctionLocation(p, lbp.Set.FunctionName, lbp.Set.Line)
	case len(lbp.Set.PidAddrs) > 0:
		for _, pidAddr := range lbp.Set.PidAddrs {
			if pidAddr.Pid == p.Pid() {
				addrs = append(addrs, pidAddr.Addr)
			}
		}
	case lbp.Set.Expr != nil:
		addrs = lbp.Set.Expr(p)
	default:
		return fmt.Errorf("breakpoint %d can not be enabled", lbp.LogicalID)
	}

	if err != nil {
		return err
	}

	for _, addr := range addrs {
		_, err = p.SetBreakpoint(lbp.LogicalID, addr, UserBreakpoint, nil)
		if err != nil {
			if _, isexists := err.(BreakpointExistsError); isexists {
				continue
			}
			return err
		}
	}

	return err
}

// DisableBreakpoint disables a logical breakpoint (or watchpoint).
func (grp *TargetGroup) DisableBreakpoint(lbp *LogicalBreakpoint) error {
	var errs []error
	n := 0
	it := ValidTargets{Group: grp}
	for it.Next() {
		for _, bp := range it.Breakpoints().M {
			if bp.LogicalID() == lbp.LogicalID {
				n++
				err := it.ClearBreakpoint(bp.Addr)
				if err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	if len(errs) > 0 {
		buf := new(bytes.Buffer)
		for i, err := range errs {
			fmt.Fprintf(buf, "%s", err)
			if i != len(errs)-1 {
				fmt.Fprintf(buf, ", ")
			}
		}

		if len(errs) == n {
			return fmt.Errorf("unable to clear breakpoint %d: %v", lbp.LogicalID, buf.String())
		}
		return fmt.Errorf("unable to clear breakpoint %d (partial): %s", lbp.LogicalID, buf.String())
	}
	lbp.Enabled = false
	return nil
}

// FollowExec enables or disables follow exec mode. When follow exec mode is
// enabled new processes spawned by the target process are automatically
// added to the target group.
// If regex is not the empty string only processes whose command line
// matches regex will be added to the target group.
func (grp *TargetGroup) FollowExec(v bool, regex string) error {
	grp.followExecRegex = nil
	if regex != "" && v {
		var err error
		grp.followExecRegex, err = regexp.Compile(regex)
		if err != nil {
			return err
		}
	}
	it := ValidTargets{Group: grp}
	for it.Next() {
		err := it.Proc.FollowExec(v)
		if err != nil {
			return err
		}
	}
	grp.followExecEnabled = v
	return nil
}

// FollowExecEnabled returns true if follow exec is enabled
func (grp *TargetGroup) FollowExecEnabled() bool {
	return grp.followExecEnabled
}

// ValidTargets iterates through all valid targets in Group.
type ValidTargets struct {
	*Target
	Group *TargetGroup
	start int
}

// Next moves to the next valid target, returns false if there aren't more
// valid targets in the group.
func (it *ValidTargets) Next() bool {
	for i := it.start; i < len(it.Group.targets); i++ {
		if ok, _ := it.Group.targets[i].Valid(); ok {
			it.Target = it.Group.targets[i]
			it.start = i + 1
			return true
		}
	}
	it.start = len(it.Group.targets)
	it.Target = nil
	return false
}

// Reset returns the iterator to the start of the group.
func (it *ValidTargets) Reset() {
	it.Target = nil
	it.start = 0
}
