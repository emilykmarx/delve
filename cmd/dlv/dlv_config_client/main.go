package main

import (
	"flag"
	"fmt"
	"log"
	"slices"

	"github.com/go-delve/delve/service/api"
	"github.com/go-delve/delve/service/rpc2"
)

// PERF: Avoid re-parsing files

// One round of replay
func (tc *TaintCheck) replay() {
	//fmt.Printf("\n\n*** Begin replay\n")
	if tc.nWps(true) > 0 {
		log.Fatalf("Existing watchpoints at start of replay")
	}
	state := <-tc.client.Continue()

	for ; !state.Exited; state = <-tc.client.Continue() {
		if state.Err != nil {
			log.Fatalf("Error in debugger state: %v\n", state.Err)
		}

		for _, thread := range state.Threads {
			hit_bp := thread.Breakpoint
			if hit_bp != nil {
				tc.hit = Hit{hit_bp: hit_bp}
				// TODO see gdoc (Instr that would hit multiple*) - may need more logic here for multiple hits
				if hit_bp.WatchExpr != "" {
					// Note PC has advanced one past the breakpoint by now, for hardware breakpoints (but not software)
					// TODO ignore if spurious, or if a go runtime thread
					//fmt.Printf("Client: hit wp for %#x, PC %#x\n", hit_bp.Addr, thread.PC)
					//tc.onWatchpointHit()
				} else {
					// Assumes the hit bp is for a pending wp (but could instead be e.g. fatalpanic)
					if slices.Contains(int_0x3_addrs, hit_bp.Addr) {
						fmt.Printf("Hit int 0x3 at %#x\n", hit_bp.Addr)
						tc.printStacktrace()
					} else {
						tc.onPendingWpBpHit()
					}
				}
			}
		}

		for _, wp_oos := range state.WatchOutOfScope {
			//fmt.Printf("Watchpoint on 0x%x went out of scope since last continue\n", wp_oos.Addrs[0])
			delete(tc.mem_param_map, wp_oos.Addrs[0])
		}
	}

	for wp, tainting_vals := range tc.round_done_wps {
		tc.done_wps[wp] = tainting_vals
	}
	tc.round_done_wps = make(map[DoneWp]TaintingVals)

	//fmt.Printf("Target exited with status %v\n", state.ExitStatus)
	tc.client.Restart(false)

	// Clear wp but keep bp (after restart - if target exited, seems we're unable to list bps)
	bps, list_err := tc.client.ListBreakpoints(true)
	if list_err != nil {
		log.Fatalf("Error listing breakpoints: %v\n", list_err)
	}
	for _, bp := range bps {
		if bp.WatchExpr != "" {
			tc.client.ClearBreakpoint(bp.ID)
		}
	}

}

var (
	int_0x3_addrs = []uint64{
		//0x469193, 0x46ae00, 0x46c657, 0x46cb89, // int 0x3
		//0x46cb80, // sigaction - happens a lot (used to return from trap I think)
		//0x46d780, 0x4562c0, // badsystemstack
		//0x46c640, // exitthread
		// abort already set
		0x46920e, 0x469221, // bad things in morestack
	}
)

func main() {
	//fmt.Printf("Starting delve config client\n\n")
	log.SetFlags(log.Lshortfile)
	initial_bp_file := flag.String("initial_bp_file", "", "File to set initial breakpoint")
	initial_bp_line := flag.Int("initial_bp_line", 0, "Line number to set initial breakpoint")
	initial_watchexpr := flag.String("initial_watchexpr", "", "Expression to set initial watchpoint")
	flag.Parse()

	listenAddr := "localhost:4040"
	client := rpc2.NewClient(listenAddr)

	// TODO somehow prevent compiler from reading watched vars from registers -
	// runtime.KeepAlive() helps, but only if placed correctly (at end of scope doesn't always work)

	tc := TaintCheck{client: client,
		pending_wps: make(map[uint64]PendingWp),
		done_wps:    make(map[DoneWp]TaintingVals), round_done_wps: make(map[DoneWp]TaintingVals),
		mem_param_map: make(map[uint64]TaintingVals)}
	init_loc := tc.lineWithStmt(nil, *initial_bp_file, *initial_bp_line, 0)
	//init_loc = api.Location{PCs: []uint64{0x49d510}}
	init_loc = api.Location{PCs: []uint64{0x46743a}}

	//init_loc = api.Location{PCs: []uint64{0x49b2c1}}
	/*
		for _, int_0x3_addr := range int_0x3_addrs {
			tc.setBp(int_0x3_addr)
		}
		int_0x3_fns := []string{"runtime.exitThread",
			//"runtime.sigreturn__sigaction", // normal
			"runtime.abort",
			"runtime.sigpanic",
			"runtime.badsystemstack", // from runtime.systemstack.abi0
			"runtime.badmorestackg0",
			"runtime.badmorestackgsignal",
			"runtime.badctxt",
		}
		for _, int_0x3_fn := range int_0x3_fns {
			bp := api.Breakpoint{FunctionName: int_0x3_fn}
			if _, err := tc.client.CreateBreakpoint(&bp); err != nil {
				if !strings.HasPrefix(err.Error(), "Breakpoint exists at") {
					log.Fatalf("Failed to create breakpoint at %v: %v\n", int_0x3_fn, err)
				}
			}
		}
	*/

	// This will be replaced by a config breakpoint
	//fmt.Printf("Configuration variable: %v\n", *initial_watchexpr)
	tc.recordPendingWp(*initial_watchexpr, init_loc, nil)

	for len(tc.pending_wps) > 0 {
		tc.replay()
	}

	//fmt.Println("Detaching delve config client")
	client.Detach(false)
}
