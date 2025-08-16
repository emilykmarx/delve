package conftamer

import (
	"encoding/csv"
	"fmt"
	"log"
	"log/slog"
	"strings"

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

func (tc *TaintCheck) getChanInfo(goroutine int64) {
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

	// Get context on where chan was declared
	if goroutine == 1 {
		// If main goroutine, line in main
		main_loc := stack[len(stack)-3]
		chan_info.decl_main_lineno = main_loc.Line
		chan_info.decl_main_line = sourceLine(tc.client, main_loc.File, main_loc.Line)
	} else {
		// spawn/fct decl loc: -g, -s
		filters := []api.ListGoroutinesFilter{
			{Kind: api.GoroutineUser},
			{Kind: api.GoroutineCurrentLoc, Arg: fmt.Sprintf("%v:%v", chan_file, makechan_ret_line)},
		}
		goroutines, _, _, _, err := tc.client.ListGoroutinesWithFilter(0, 0, filters, nil, &scope)
		if err != nil {
			log.Panicf("listing goroutines: %v", err)
		}

		for _, g := range goroutines {
			if g.ID == goroutine {
				// If multiple goroutines hit the bp, find the one we're currently handling
				chan_info.go_spawn_loc = fmt.Sprintf("%v:%v", g.GoStatementLoc.File, g.GoStatementLoc.Line)
				chan_info.go_fn_loc = fmt.Sprintf("%v:%v", g.StartLoc.File, g.StartLoc.Line)
			}
		}

	}

	// Stacktrace of declaring goroutine
	for _, frame := range stack {
		chan_info.go_stack = append(chan_info.go_stack, fmt.Sprintf("%v:%v", frame.File, frame.Line))
	}

	WriteChanInfo(tc.chan_log, chan_addr, chan_info)
}

// Assuming target is stopped, handle breakpoint/watchpoint hits across all threads.
// Return false if we hit the end of range bp instead of a makechan bp
func (tc *TaintCheck) handleTargetStop(state *api.DebuggerState, chandecl_end_bp int, makechan_bp int) bool {
	for _, thread := range state.Threads {
		hit_bp := thread.Breakpoint
		if hit_bp != nil {
			switch hit_bp.ID {
			case chandecl_end_bp:
				return false
			case makechan_bp:
				tc.getChanInfo(thread.GoroutineID)
			default:
				log.Panicf("Hit unexpected breakpoint/watchpoint %+v on thread %v\n", hit_bp, thread.ID)
			}
		}
	}

	return true
}

func WriteChanInfo(w *csv.Writer, addr uint64, info ChanInfo) {
	row := []string{fmt.Sprintf("%#x", addr), info.name, fmt.Sprintf("%v", info.goroutineID),
		fmt.Sprintf("%v", info.decl_main_lineno), info.decl_main_line,
		info.go_spawn_loc, info.go_fn_loc,
		strings.Join(info.go_stack, "\n")}

	if err := w.WriteAll([][]string{row}); err != nil {
		log.Panicf("writing chan %v: %v\n", row, err.Error())
	}
}

func (tc *TaintCheck) Run() {
	tc.Logf(slog.LevelInfo, nil, "Starting CT-Scan")
	tc.chan_log.Write([]string{"Memory Address", "Name", "Goroutine ID",
		"main() lineno", "main() line",
		"Goroutine spawn", "Goroutine fn decl",
		"Goroutine stack"})
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
