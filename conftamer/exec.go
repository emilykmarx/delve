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
			} else {
				// Assumes the hit bp is for a pending wp (but could instead be e.g. fatalpanic)
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

// If command not done (i.e. was interrupted by some other hit), return what command to execute next
func (tc *TaintCheck) commandDone(cmd Command, state *api.DebuggerState, thread *api.Thread) string {
	fmt.Printf("ZZEM enter commandDone; cmd %v\n", cmd)
	defer func() {
		fmt.Printf("ZZEM exit commandDone\n")
	}()
	stack, err := tc.client.Stacktrace(-1, 100, api.StacktraceSimple, &api.LoadConfig{})
	if err != nil {
		log.Panicf("Error getting stacktrace: %v\n", err)
	}
	if state.NextInProgress {
		// Hit on another goroutine => continue (next is not allowed - continue will act as next)
		return api.Continue
	} else if len(stack) != cmd.stack_len {
		fmt.Println("ZZEM interrupted, not at right frame yet => stepout")
		return api.StepOut
	} else if cmd.cmd == api.Next && thread.Line == cmd.lineno {
		fmt.Println("ZZEM interrupted, not at right line yet => next again")
		return api.Next
	}

	// Command done
	return ""
}

// Run the target until exit
func (tc *TaintCheck) Run() {
	log.Printf("Starting CT-Scan\n\n")
	defer WriteBehaviorMap(tc.config.Behavior_map_filename, tc.behavior_map)

	var err error
	state := &api.DebuggerState{}
	// The command to execute on next target start
	cmd := api.Continue
	// If executing a command sequence, the index in the sequence
	cmd_idx := 0

	for {
		// Start target
		if cmd == api.Next {
			loc := state.SelectedGoroutine.CurrentLoc
			fmt.Printf("ZZEM next from %v\n", loc.Line)
			state, err = tc.client.Next()
			if err != nil {
				log.Panicf("Next: %v\n", err)
			}
		} else if cmd == api.StepOut {
			loc := state.SelectedGoroutine.CurrentLoc
			fmt.Printf("ZZEM stepout from %v\n", loc.Line)
			state, err = tc.client.StepOut()
			if err != nil {
				log.Panicf("Stepout: %v\n", err)
			}
		} else if cmd != api.Continue {
			log.Panicf("unsupported cmd in sequence: %v\n", cmd)
		} else {
			fmt.Printf("ZZEM continue\n")
			state = <-tc.client.Continue()
		}
		if state.Exited {
			break
		}
		if state.Err != nil {
			log.Panicf("Error in debugger state: %v\n", state.Err)
		}

		// Target stopped => handle hits, which may generate requests to execute commands needed to set watchpoints.
		// TODOs for command requests: handle multiple outstanding command requests and goroutine switching (see notebook),
		// switch ReturnStmt and copy builtin from assuming linear flow
		prev_cmd_pending_wp := tc.cmd_pending_wp
		// May populate/update tc.cmd_pending_wp
		tc.handleTargetStop(state)

		fmt.Printf("ZZEM handledTargetStop; cmd idx %v\n", cmd_idx)
		cmd = api.Continue

		if prev_cmd_pending_wp != nil {
			// Trying to finish a command in sequence => check if it's done
			thread := getThread(tc.cmd_pending_wp.threadID, state)
			cmd = tc.commandDone(tc.cmd_pending_wp.cmds[cmd_idx], state, thread)
			if cmd == "" {
				cmd = api.Continue
				if cmd_idx == len(tc.cmd_pending_wp.cmds)-1 {
					fmt.Println("ZZEM finished command sequence => set watchpoints")
					// Finished command sequence => set watchpoints
					if tc.cmd_pending_wp.body_start != 0 {
						// Finished next in branch body
						if tc.cmd_pending_wp.body_start <= thread.Line && thread.Line <= tc.cmd_pending_wp.body_end {
							fmt.Printf("ZZEM line %v: Finished next in branch body - will propagate taint, then set wp (if any)\n", thread.Line)
							// Still in branch body =>
							// Set pending watchpoint from previous line
							// Record new pending watchpoint for this line, as if we hit a watchpoint and isTainted was always true
							// Next again to set the new watchpoint
							if tc.cmd_pending_wp.watchexprs.Empty() {
								// First line of a branch body => no watchpoint to set yet - or,
								// propagateTaint from previous line found no exprs that required nexting to set wp
							} else {
								// Keep rest of cmd_pending_wp for next line
								tc.setPendingWatchpoints(tc.cmd_pending_wp, thread, 0)
							}
							cmd = api.Next
							tc.propagateTaint(thread.File, thread.Line, nil, 0) // after set previous watchpoint, since this will modify it
							// Fix lineno - pendingWatchpoint will copy it from previous
							tc.cmd_pending_wp.cmds[0].lineno = thread.Line
						} else {
							// Exited branch body => set the watchpoints from last line (if any), then stop nexting
							if !tc.cmd_pending_wp.watchexprs.Empty() {
								tc.setPendingWatchpoints(tc.cmd_pending_wp, thread, 0)
							}
							tc.cmd_pending_wp = nil
						}
					} else {
						// Not in branch body
						tc.setPendingWatchpoints(tc.cmd_pending_wp, thread, 0)
						tc.cmd_pending_wp = nil
					}
				} else {
					// Finished command, but not the whole sequence => do next command in sequence
					cmd_idx++
					cmd = tc.cmd_pending_wp.cmds[cmd_idx].cmd
				}
			}
		} else if tc.cmd_pending_wp != nil {
			// New request for sequence of commands
			fmt.Printf("ZZEM new request %+v\n", tc.cmd_pending_wp)
			cmd_idx = 0
			cmd = tc.cmd_pending_wp.cmds[cmd_idx].cmd
			fmt.Printf("ZZEM starting sequence %+v\n", tc.cmd_pending_wp.cmds)
		}
	}

	fmt.Printf("Target exited with status %v\n", state.ExitStatus)
	log.Println("Finished CT-Scan")
	tc.client.Detach(false) // Also kills server, despite function doc (even on unmodified dlv)
}
