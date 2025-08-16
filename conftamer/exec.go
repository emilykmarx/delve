package conftamer

import (
	"fmt"
	"log"
	"log/slog"

	"github.com/go-delve/delve/service/api"
)

const (
	chan_file         = "/usr/local/go/src/runtime/chan.go"
	makechan_ret_line = 124
	chandecl_file     = "/home/emily/prometheus/cmd/prometheus/main.go"
	chandecl_end_line = 1065
)

/* Functions to start the target, and
 * dispatcher to handle target stop. */

func (tc *TaintCheck) getChanInfo(goroutine int64, hit *Hit) {
	chan_info := ChanInfo{goroutineID: goroutine}
	// Get channel name from declaring frame (frame 1)
	stack, err := tc.client.Stacktrace(goroutine, 100, api.StacktraceSimple, &api.LoadConfig{})
	if err != nil {
		log.Panicf("Error getting stacktrace: %v\n", err)
	}
	decl_loc := stack[1].Location
	// Only get channel name if declared with `=` (with single lhs) or `:=` for now -
	// other common cases include ": ", but in any case should be easy to manually ID given the declaring location
	chan_name, _ := getLhs(0, decl_loc.File, decl_loc.Line)
	if chan_name != nil {
		chan_info.name = *chan_name
	}
	// Get channel addr: p c
	scope := api.EvalScope{GoroutineID: goroutine}
	chan_var, err := tc.client.EvalVariable(scope, "c", api.LoadConfig{})
	if err != nil {
		log.Panicf("no retval in makechan: %v", err)
	}
	// NOTE: my dlv can't read c, but new dlv can...maybe due to go version mismatch
	chan_addr := uint64(0) // the value of the *chan, i.e. addr of the chan
	if _, err := fmt.Sscanf(chan_var.Value, "%d", &chan_addr); err != nil {
		log.Panicf("converting chan addr to hex: %v", err)
	}

	// Get context on the goroutine (ID, spawn/fct decl loc): -g, -s
	filters := []api.ListGoroutinesFilter{
		{Kind: api.GoroutineUser},
		{Kind: api.GoroutineCurrentLoc, Arg: fmt.Sprintf("%v:%v", chan_file, makechan_ret_line)},
	}
	// If multiple goroutines hit the bp, find the one we're currently handling
	goroutines, _, _, _, err := tc.client.ListGoroutinesWithFilter(0, 0, filters, nil, &scope)
	if err != nil {
		log.Panicf("listing goroutines: %v", err)
	}
	// XXX get the spawn and decl loc, and other info that will be useful for grouping - maybe the whole stacktrace for now
	_ = goroutines

	// Get context on where chan was declared: if main goroutine, line in main
	if goroutine == 1 {
		main_loc := stack[len(stack)-3]
		chan_info.decl_main_line = main_loc.Line
	}
	WriteChanInfo(tc.chan_log, chan_addr, chan_info)
}

// Assuming target is stopped, handle breakpoint/watchpoint hits across all threads.
// Return false if we hit the end of range bp instead of a makechan bp
func (tc *TaintCheck) handleTargetStop(state *api.DebuggerState, chandecl_end_bp int, makechan_bp int) bool {

	for _, thread := range state.Threads {
		hit_bp := thread.Breakpoint
		if hit_bp != nil {
			hit := &Hit{hit_bp: hit_bp, thread: thread, scope: api.EvalScope{GoroutineID: -1}}
			// TODO see gdoc (Instr that would hit multiple*) - may need more logic here for multiple hits
			if hit_bp.ID == chandecl_end_bp {
				return false
			} else if hit_bp.ID == makechan_bp {
				tc.getChanInfo(thread.GoroutineID, hit)
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
	chandecl_end_bp, err := tc.client.CreateBreakpoint(&api.Breakpoint{File: chandecl_file, Line: chandecl_end_line})
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
	// TODO (minor): check we're at the range start bp
	makechan_bp, err := tc.client.CreateBreakpoint(&api.Breakpoint{File: chan_file, Line: makechan_ret_line})
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

		if !tc.handleTargetStop(state, chandecl_end_bp.ID, makechan_bp.ID) {
			// End of range
			tc.Logf(slog.LevelInfo, nil, "Reached end of channel declaration range")
			break
		}

	}

	tc.Logf(slog.LevelInfo, nil, "Finished CT-Scan - target exited with status %v", state.ExitStatus)
	tc.client.Detach(false) // Also kills server, despite function doc (even on unmodified dlv)
}
