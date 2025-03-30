package conftamer

import (
	"fmt"
	"log"

	"github.com/go-delve/delve/pkg/proc"
	"github.com/go-delve/delve/service/api"
)

/* Functions to start the target, and
 * dispatcher to handle target stop. */

// Assuming target is stopped, handle breakpoint/watchpoint hits across all threads.
func (tc *TaintCheck) handleTargetStop(state *api.DebuggerState) {
	tc.updateMovedWps()

	for _, thread := range state.Threads {
		hit_bp := thread.Breakpoint
		if hit_bp != nil {
			hit := &Hit{hit_bp: hit_bp, thread: thread}
			// TODO see gdoc (Instr that would hit multiple*) - may need more logic here for multiple hits
			if hit_bp.Name == proc.SyscallEntryBreakpoint {
				tc.handleSyscallEntry(hit)
			} else if hit_bp.WatchExpr != "" {
				tc.onWatchpointHit(hit)
			} else if hit_bp.Name == proc.UnrecoveredPanic || hit_bp.Name == proc.FatalThrow || hit_bp.Name == proc.HardcodedBreakpoint ||
				hit_bp.Name == proc.SyscallExitBreakpoint {
				log.Panicf("Hit unexpected breakpoint %+v on thread %v\n", hit_bp, thread.ID)
			} else {
				tc.onPendingWpBpHit(hit)
			}
		}
	}

	// TODO also need to remove any PreviousAddrs?
	for _, wp_oos := range state.WatchOutOfScope {
		loc := state.SelectedGoroutine.CurrentLoc
		fmt.Printf("Watchpoint on %v went out of scope - current goroutine at %v:%v (0x%x) \n",
			wp_oos.WatchExpr, loc.File, loc.Line, loc.PC)
		forEachWatchaddr(wp_oos, func(watchaddr uint64) bool {
			delete(tc.mem_param_map, watchaddr)
			return true // unused
		})
	}
}

// If command not done (i.e. was interrupted by some other hit), return what command to execute next.
// Return true if have exited the command's frame (i.e. stack shorter, vs longer indicating interrupted by function call).
func (tc *TaintCheck) commandDone(cmd Command, state *api.DebuggerState, thread *api.Thread) (string, bool) {
	stack := tc.stacktrace()
	if state.NextInProgress {
		// Hit on another goroutine => continue (next is not allowed - continue will act as next)
		return api.Continue, false
	} else if len(stack) > cmd.stack_len {
		fmt.Printf("ZZEM interrupted at line %v, not at right frame yet => stepout\n", thread.Line)
		return api.StepOut, false
	} else if len(stack) < cmd.stack_len {
		fmt.Printf("ZZEM exited command frame at line %v\n", thread.Line)
		return api.Continue, true
	} else if cmd.cmd == api.Next && thread.Line == cmd.lineno {
		fmt.Printf("ZZEM interrupted at line %v, not at right line yet => next again", thread.Line)
		return api.Next, false
	}

	// Command done
	return "", false
}

// Run the target until exit
// TODOs for command requests: handle multiple outstanding command requests and goroutine switching (see notebook),
// switch ReturnStmt and copy builtin from assuming linear flow
func (tc *TaintCheck) Run() {
	log.Printf("Starting CT-Scan\n\n")
	defer WriteBehaviorMap(tc.config.Behavior_map_filename, tc.behavior_map)

	state := &api.DebuggerState{}
	// The command to execute on next target start
	cmd := api.Continue
	// If executing a command sequence, the index in the sequence
	cmd_idx := 0
	// Whether we've exited the command's frame
	exited_frame := false

	for {
		// Start target, wait for stop
		tc.startTarget(cmd, state)
		if state.Exited {
			break
		}
		if state.Err != nil {
			log.Panicf("Error in debugger state: %v\n", state.Err)
		}

		// Target stopped => check if last start finished the command we were executing
		// (if any besides Continue)
		if tc.cmd_pending_wp != nil {
			thread := getThread(tc.cmd_pending_wp.threadID, state)
			cmd, exited_frame = tc.commandDone(tc.cmd_pending_wp.cmds[cmd_idx], state, thread)
			if cmd == "" || exited_frame {
				if cmd_idx == len(tc.cmd_pending_wp.cmds)-1 {
					// Finished command sequence => set watchpoints
					fmt.Printf("ZZEM finished sequence - at line %v; pending wp %+v\n", thread.Line, tc.cmd_pending_wp)
					if tc.cmd_pending_wp.body_start != 0 {
						// Finished next in branch body
						if tc.cmd_pending_wp.body_start <= thread.Line && thread.Line <= tc.cmd_pending_wp.body_end && !exited_frame {
							// Still in branch body =>
							// Set pending watchpoint from previous line
							// Record new pending watchpoint for this line, as if we hit a watchpoint and isTainted was always true
							// Next again to set the new watchpoint
							if tc.cmd_pending_wp.watchexprs.Empty() {
								// First line of a branch body => no watchpoint to set yet - or,
								// propagateTaint from previous line found no exprs that required nexting to set wp
								fmt.Printf("ZZEM first line\n")
							} else {
								// Keep rest of cmd_pending_wp, including its tainting values and command =>
								// will keep nexting and setting watchpoints tainted by condition until exit body
								fmt.Printf("ZZEM non-first line\n")
								tc.setPendingWatchpoints(tc.cmd_pending_wp, thread, 0)
							}
							// Make a "hit" with the info propagateTaint needs
							instr := api.AsmInstruction{Loc: api.Location{File: thread.File, Line: thread.Line}}
							hit := Hit{thread: thread, hit_instr: &instr, stack_len: len(tc.stacktrace())}
							tainted_region := tc.propagateTaint(&hit) // after set previous watchpoint, since this will modify it
							if tainted_region != nil {
								tc.pendingWatchpoint(tainted_region, &hit)
							}
						} else {
							// Exited branch body, either by nexting past last line or returning from it =>
							// Set the watchpoints from last line (if any), then stop nexting
							fmt.Printf("exited branch body\n")
							if !tc.cmd_pending_wp.watchexprs.Empty() {
								tc.setPendingWatchpoints(tc.cmd_pending_wp, thread, 0)
							}
							tc.cmd_pending_wp = nil
							cmd_idx = 0
						}
					} else {
						fmt.Printf("ZZEM not in branch body - set cmd pending wp\n")
						// Not in branch body
						tc.setPendingWatchpoints(tc.cmd_pending_wp, thread, 0)
						tc.cmd_pending_wp = nil
						cmd_idx = 0
					}
				} else {
					// Finished command, but not the whole sequence => do next command in sequence
					fmt.Printf("ZZEM finished command but not whole sequence\n")
					cmd_idx++
				}
			}
		}

		// Handle hits, which may generate requests to execute commands needed to set watchpoints.
		// May populate/update tc.cmd_pending_wp
		tc.handleTargetStop(state)

		if tc.cmd_pending_wp != nil {
			cmd = tc.cmd_pending_wp.cmds[cmd_idx].cmd
			fmt.Printf("ZZEM doing next cmd in seq: %+v\n", cmd)
		} else {
			fmt.Printf("ZZEM doing continue\n")
			cmd = api.Continue
		}
	}

	fmt.Printf("Target exited with status %v\n", state.ExitStatus)
	log.Println("Finished CT-Scan")
	tc.client.Detach(false) // Also kills server, despite function doc (even on unmodified dlv)
}
