package conftamer

import (
	"log"
	"log/slog"

	"github.com/go-delve/delve/service/api"
)

/* Functions to start the target, and
 * dispatcher to handle target stop. */

// Assuming target is stopped, handle breakpoint/watchpoint hits across all threads.
// Return false if we hit the end of range bp instead of a makechan bp
func (tc *TaintCheck) handleTargetStop(state *api.DebuggerState, range_end_bp int, makechan_bp int) bool {

	for _, thread := range state.Threads {
		hit_bp := thread.Breakpoint
		if hit_bp != nil {
			hit := &Hit{hit_bp: hit_bp, thread: thread, scope: api.EvalScope{GoroutineID: -1}}
			// TODO see gdoc (Instr that would hit multiple*) - may need more logic here for multiple hits
			if hit_bp.ID == range_end_bp {
				tc.Logf(slog.LevelDebug, hit, "REACHED END OF CHANNEL DECLARATION RANGE")
				return false
			} else if hit_bp.ID == makechan_bp {
				tc.Logf(slog.LevelDebug, hit, "MAKECHAN")
				tc.printStacktrace()
				log.Panic()
			} else {
				log.Panicf("Hit unexpected breakpoint/watchpoint %+v on thread %v\n", hit_bp, thread.ID)
			}
		}
	}

	return true
}

func (tc *TaintCheck) Run() {
	tc.Logf(slog.LevelInfo, nil, "Starting CT-Scan")
	// 1. Set bp at beginning and end of range where shared channels are declared
	if _, err := tc.client.CreateBreakpoint(&api.Breakpoint{FunctionName: "main.main"}); err != nil {
		log.Panicf("range start bp: %v", err)
	}
	range_end_line := 1065
	range_end_bp, err := tc.client.CreateBreakpoint(&api.Breakpoint{File: "/home/emily/prometheus/cmd/prometheus/main.go", Line: range_end_line})
	if err != nil {
		log.Panicf("range end bp: %v", err)
	}

	state := &api.DebuggerState{}
	// The command to execute on next target start
	cmd := api.Continue
	// 2. Continue to beginning of range, set bp on end of makechan
	tc.startTarget(cmd, state)
	if state.Exited || state.Err != nil {
		log.Panicf("continue to main.main: %+v\n", state)
	}
	makechan_bp, err := tc.client.CreateBreakpoint(&api.Breakpoint{File: "/usr/local/go/src/runtime/chan.go", Line: 124})
	if err != nil {
		log.Panicf("makechan bp: %v", err)
	}

	for {
		// 3. Continue through makechan bps until end of range
		tc.startTarget(cmd, state)
		if state.Exited {
			break
		}
		if state.Err != nil {
			log.Panicf("Error in debugger state: %v\n", state.Err)
		}

		// Target stopped
		tc.handleTargetStop(state, range_end_bp.ID, makechan_bp.ID)

	}

	tc.Logf(slog.LevelInfo, nil, "Finished CT-Scan - target exited with status %v", state.ExitStatus)
	tc.client.Detach(false) // Also kills server, despite function doc (even on unmodified dlv)
}
