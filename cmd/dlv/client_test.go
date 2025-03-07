package main_test

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	ct "github.com/go-delve/delve/conftamer"
	protest "github.com/go-delve/delve/pkg/proc/test"
	"github.com/google/go-cmp/cmp"
	set "github.com/hashicorp/go-set"
)

const (
	module   = "test_module"
	move_wps = false // for tests other than the one specific to moving wps
)

// Notes:
// Need to build target with fork of go that has allocator changes, so:
// - If run from IDE, IDE needs to be set to use that fork
// - Will build delve, client, and target with that fork of go, so they need to be compatible with it
// (e.g. go 1.20.1 doesn't have max/min builtins)
// Also, some things compile differently in go 1.20.1 vs 1.22.4 (in ways that matter for tests)

// Build client
func getClientBin(t *testing.T) string {
	clientbin := filepath.Join(t.TempDir(), "client.exe")
	args := []string{"build", "-o", clientbin}
	build_arg := "github.com/go-delve/delve/cmd/dlv/conftamer_main"
	args = append(args, build_arg)

	out, err := exec.Command("go", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("go %v: %v\n%s", args, err.Error(), string(out))
	}

	return clientbin
}

// Check behavior map read/write to file, and equality operations on it
func TestReadWriteBehaviorMap(t *testing.T) {
	behavior := ct.BehaviorValue{Offset: 1, Send_endpoint: "send_endpoint", Recv_endpoint: "recv_endpoint", Transport: "tcp", Send_module: "send_module"}
	tainting_behavior := ct.TaintingBehavior{
		Behavior: behavior,
		Flow:     ct.DataFlow,
	}
	tainting_vals := ct.TaintingVals{
		// params empty to check empty sets can still marshal/unmarshal
		Behaviors: *set.From([]ct.TaintingBehavior{tainting_behavior}),
	}
	behavior_map := make(ct.BehaviorMap)
	behavior_map[behavior] = tainting_vals

	file := filepath.Join(t.TempDir(), "behavior_map.csv")
	assertNoError(ct.WriteBehaviorMap(file, behavior_map), t, "write")
	behavior_map_2, err := ct.ReadBehaviorMap(file)
	assertNoError(err, t, "read")

	// Check equality (and that read/write worked)
	if diff := cmp.Diff(behavior_map, behavior_map_2); diff != "" {
		t.Fatalf("Map before read != after\nDiff: %v\nBefore: %v\nAfter: %v",
			diff, behavior_map, behavior_map_2)
	}

	// Check inequality
	tainting_behavior.Flow = ct.ControlFlow
	tainting_vals = ct.TaintingVals{
		Behaviors: *set.From([]ct.TaintingBehavior{tainting_behavior}),
	}
	behavior_map[behavior] = tainting_vals

	if diff := cmp.Diff(behavior_map, behavior_map_2); diff == "" {
		t.Fatalf("Failed to detect inequality: %v vs %v\n",
			behavior_map, behavior_map_2)
	}
}

// Assuming `config` taints the entire watch region, append watchpoint set and
// corresponding mem-param update events
// If additional taint is passed, add that
func watchpointSet(config string, watchexpr string, sz uint64, line int, flow ct.TaintFlow,
	extra_tainting_param *ct.TaintingParam) []ct.Event {
	events := []ct.Event{}
	events = append(events, ct.Event{
		EventType:  ct.WatchpointSet,
		Size:       sz,
		Expression: watchexpr,
		Line:       line,
	})

	tainting_param := ct.TaintingParam{
		Module: module,
		Param:  config,
		Flow:   flow,
	}
	tainting_params := set.From([]ct.TaintingParam{tainting_param})
	if extra_tainting_param != nil {
		tainting_params.Insert(*extra_tainting_param)
	}
	tainting_vals := ct.TaintingVals{
		Params: *tainting_params,
	}
	for offset := uint64(0); offset < sz; offset++ {
		events = append(events, ct.Event{
			// run() will fill in address from wp set
			EventType: ct.MemParamMapUpdate, TaintingVals: &tainting_vals, Line: line,
		})
	}
	return events
}

func TestControlFlow(t *testing.T) {
	// 1. Set wp for config
	config := "config"
	expected_events :=
		watchpointSet(config, config, uint64(len(config)), 10, ct.DataFlow, nil)

	// 2. Hit wp in if condition => propagate to maybe_tainted
	expected_events = append(expected_events,
		watchpointSet(config, "maybe_tainted", 3, 18, ct.ControlFlow, nil)...)

	expected_events = append(expected_events,
		watchpointSet(config, "maybe_tainted_2", 1, 21, ct.ControlFlow, nil)...)

	dataflow_taint := ct.TaintingParam{
		Module: module,
		Param:  config,
		Flow:   ct.DataFlow,
	}
	expected_events = append(expected_events,
		watchpointSet(config, "regular", 1, 22, ct.ControlFlow, &dataflow_taint)...)

	expected_events = append(expected_events,
		watchpointSet(config, "maybe_tainted_3", 1, 31, ct.ControlFlow, nil)...)

	expected_events = append(expected_events,
		watchpointSet(config, "maybe_tainted_4", 1, 38, ct.ControlFlow, nil)...)

	expected_events = append(expected_events,
		watchpointSet(config, "i", 1, 39, ct.ControlFlow, nil)...)

	expected_events = append(expected_events,
		watchpointSet(config, "j", 1, 40, ct.DataFlow, nil)...)

	run(t, "control_flow.go", expected_events, nil, move_wps)
}

// Tests clear when another sw wp still exists on same page
func TestCallAndAssign1(t *testing.T) {
	config := "stack"
	expected_events :=
		watchpointSet(config, config, uint64(8), 31, ct.DataFlow, nil)

	expected_events = append(expected_events,
		watchpointSet(config, "spacer", uint64(8), 35, ct.DataFlow, nil)...)

	expected_events = append(expected_events,
		watchpointSet(config, "tainted_param", uint64(8), 15, ct.DataFlow, nil)...)

	expected_events = append(expected_events,
		watchpointSet(config, "tainted_param_2", uint64(8), 21, ct.DataFlow, nil)...)

	expected_events = append(expected_events,
		watchpointSet(config, "y", uint64(8), 42, ct.DataFlow, nil)...)

	expected_events = append(expected_events,
		watchpointSet(config, "z", uint64(8), 46, ct.DataFlow, nil)...)

	run(t, "call_assign_1.go", expected_events, nil, move_wps)
}

func TestCallAndAssign2(t *testing.T) {
	config := "stack"
	expected_events :=
		watchpointSet(config, config, uint64(8), 19, ct.DataFlow, nil)

	expected_events = append(expected_events,
		watchpointSet(config, "tainted_param_2", uint64(8), 10, ct.DataFlow, nil)...)

	expected_events = append(expected_events,
		watchpointSet(config, "a", uint64(8), 22, ct.DataFlow, nil)...)

	run(t, "call_assign_2.go", expected_events, nil, move_wps)
}

func TestStrings(t *testing.T) {
	config := "s"
	expected_events :=
		watchpointSet(config, config, uint64(2), 15, ct.DataFlow, nil)

	expected_events = append(expected_events,
		watchpointSet(config, "s2", uint64(6), 16, ct.DataFlow, nil)...)

	expected_events = append(expected_events,
		watchpointSet(config, "i", uint64(1), 19, ct.DataFlow, nil)...)

	run(t, "strings.go", expected_events, nil, move_wps)
}

func TestSliceRangeBuiltins(t *testing.T) {
	config := "s"
	expected_events :=
		watchpointSet(config, config, uint64(2), 15, ct.DataFlow, nil)

	expected_events = append(expected_events,
		watchpointSet(config, "s2", uint64(6), 16, ct.DataFlow, nil)...)
	// Client sets initial watch on conf.search => server sets wp on both strings
	initial_watchexpr := "conf.search"
	run(t, "slice_range_builtins.go", expected_events, &initial_watchexpr, move_wps)
}

// Slice of slices, array of slices/strings (slice of strings is in TestSliceRangeBuiltins)
// Note that this test checks the watchexpr, so it's important how the server chooses to set it -
// does so when (t *Target) SetWatchpoint calls SetWatchpointNoEval instead of telling the
// Debugger to recurse (i.e. get to a string or slice/array of non-references)
func TestReferenceElems(t *testing.T) {
	dir := "reference_elems/"

	// Array of strings => set on each string
	config := "arr_strs"
	expected_events :=
		watchpointSet(config, config+"[0]", uint64(2), 10, ct.DataFlow, nil)
	expected_events = append(expected_events,
		watchpointSet(config, config+"[1]", uint64(5), 10, ct.DataFlow, nil)...)

	run(t, dir+"arr_strs.go", expected_events, &config, move_wps)

	// Array of slices => set on each slice's strings
	config = "arr_slices"
	expected_events =
		watchpointSet(config, config+"[0][0]", uint64(2), 12, ct.DataFlow, nil)
	expected_events = append(expected_events,
		watchpointSet(config, config+"[0][1]", uint64(5), 12, ct.DataFlow, nil)...)
	expected_events = append(expected_events,
		watchpointSet(config, config+"[1][0]", uint64(3), 12, ct.DataFlow, nil)...)
	expected_events = append(expected_events,
		watchpointSet(config, config+"[1][1]", uint64(4), 12, ct.DataFlow, nil)...)
	run(t, dir+"arr_slices.go", expected_events, &config, move_wps)

	// Slice of slices => set on each inner slice's strings
	config = "slice_slices"
	expected_events =
		watchpointSet(config, config+"[0][0]", uint64(2), 12, ct.DataFlow, nil)
	expected_events = append(expected_events,
		watchpointSet(config, config+"[0][1]", uint64(5), 12, ct.DataFlow, nil)...)
	expected_events = append(expected_events,
		watchpointSet(config, config+"[1][0]", uint64(3), 12, ct.DataFlow, nil)...)
	expected_events = append(expected_events,
		watchpointSet(config, config+"[1][1]", uint64(4), 12, ct.DataFlow, nil)...)

	run(t, dir+"slice_slices.go", expected_events, &config, move_wps)
}

func TestMethods(t *testing.T) {
	config := "nested.name.Data"
	expected_events :=
		watchpointSet(config, config, uint64(2), 39, ct.DataFlow, nil)

	expected_events = append(expected_events,
		watchpointSet(config, "recvr_callee.Data", uint64(2), 27, ct.DataFlow, nil)...)

	run(t, "methods.go", expected_events, nil, move_wps)
}

func TestFuncLitGoRoutine(t *testing.T) {
	// Compiler uses same memory for chars of both fqdn strings,
	// so only expect wp for chars on 13
	config := "fqdn"
	expected_events :=
		watchpointSet(config, config, uint64(4), 14, ct.DataFlow, nil)
	run(t, "funclit_goroutine.go", expected_events, nil, move_wps)
}

func TestMultiRound(t *testing.T) {
	config := "vars[0]"
	expected_events :=
		watchpointSet(config, config, uint64(8), 11, ct.DataFlow, nil)

	for i := 0; i < 5; i++ {
		expected_events = append(expected_events,
			watchpointSet(config, "vars[i]", uint64(8), 16, ct.DataFlow, nil)...)
	}

	run(t, "multiround.go", expected_events, nil, move_wps)
}

func TestRuntimeHits(t *testing.T) {
	config := "name"
	expected_events :=
		watchpointSet(config, config, uint64(2), 21, ct.DataFlow, nil)
	// uses same backing array for name and name_callee, but n.Data and n_caller.Data each have their own

	expected_events = append(expected_events,
		watchpointSet(config, "n.Data[:]", uint64(255), 16, ct.DataFlow, nil)...)

	expected_events = append(expected_events,
		watchpointSet(config, "n_caller.Data", uint64(255), 22, ct.DataFlow, nil)...)

	run(t, "runtime_hits.go", expected_events, nil, move_wps)
}

func TestCasts(t *testing.T) {
	config := "x"
	expected_events :=
		watchpointSet(config, config, uint64(8), 11, ct.DataFlow, nil)

	expected_events = append(expected_events,
		watchpointSet(config, "y", uint64(8), 13, ct.DataFlow, nil)...)

	run(t, "casts.go", expected_events, nil, move_wps)
}

func TestNetworkSend(t *testing.T) {
	// XXX replace by splitting network_recv in two
	expected_events := []ct.Event{}

	run(t, "network_send.go", expected_events, nil, move_wps)
}
func TestNetworkRecv(t *testing.T) {
	expected_events := []ct.Event{}

	run(t, "network_recv.go", expected_events, nil, move_wps)
}
func TestStructs(t *testing.T) {
	config := "arr"
	expected_events :=
		watchpointSet(config, config, uint64(2), 26, ct.DataFlow, nil)

	expected_events = append(expected_events,
		watchpointSet(config, "struct_lit.Data", uint64(2), 27, ct.DataFlow, nil)...)

	expected_events = append(expected_events,
		watchpointSet(config, "s.Data", uint64(2), 29, ct.DataFlow, nil)...)

	expected_events = append(expected_events,
		watchpointSet(config, "s_callee.Data", uint64(2), 20, ct.DataFlow, nil)...)

	expected_events = append(expected_events,
		watchpointSet(config, "s_caller.Data", uint64(2), 31, ct.DataFlow, nil)...)

	expected_events = append(expected_events,
		watchpointSet(config, "multiline_lit.Data", uint64(2), 36, ct.DataFlow, nil)...)

	expected_events = append(expected_events,
		watchpointSet(config, "nested.name.Data", uint64(2), 41, ct.DataFlow, nil)...)

	expected_events = append(expected_events,
		watchpointSet(config, "nested2.name.Data", uint64(2), 44, ct.DataFlow, nil)...)

	run(t, "structs.go", expected_events, nil, move_wps)
}

func TestAllocatorHTTP(t *testing.T) {
	config := "*ptr"
	expected_events :=
		watchpointSet(config, config, uint64(8), 27, ct.DataFlow, nil)

	expected_events = append(expected_events,
		watchpointSet(config, "x", uint64(8), 31, ct.DataFlow, nil)...)

	run(t, "allocator_http.go", expected_events, nil, true)
}

/* TODO need to investigate this - per asm, doesn't seem like should be fake...
func TestFakeArg(t *testing.T) {
	expected_events := []ct.Event{
		{kind: CreateWatchpoint, lineno: 6, watchexpr: "addrs"},
	}

	run(t, "fake_xv.go", expected_events)
}
*/

func waitForServer(t *testing.T, stdout *saveOutput, stderr *saveOutput) {
	// Wait for server to start
	for ; len(stdout.savedOutput) == 0; time.Sleep(300 * time.Millisecond) {
	}
	if !strings.HasPrefix(string(stdout.savedOutput), "API server listening at:") {
		t.Fatalf("Delve server failed to start listening")
	}

	// Check for error
	// XXX need to fix this to account for logging in my version of go
	if len(stderr.savedOutput) > 0 {
		//t.Fatalf("Delve server errored while starting up")
	}
}

// Save output and write it to stdout
type saveOutput struct {
	savedOutput []byte
}

func (so *saveOutput) Write(p []byte) (n int, err error) {
	so.savedOutput = append(so.savedOutput, p...)
	return os.Stdout.Write(p)
}

// Client's initial watchexpr is one in the first expected_log,
// unless initial_watchexpr is passed
func run(t *testing.T, testfile string, expected_events []ct.Event, initial_watchexpr *string, move_wps bool) {
	// Start dlv server
	listenAddr := "localhost:4040"
	fixturePath := filepath.Join(protest.FindFixturesDir(), "conftamer", testfile)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Remove testfile binary
	defer func() {
		entries, err := os.ReadDir("./")
		assertNoError(err, t, "readdir to remove testfile binary")

		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "__debug_bin") {
				assertNoError(os.Remove(e.Name()), t, "remove testfile binary")
			}
		}
	}()

	var server_out saveOutput
	var server_err saveOutput

	server := exec.CommandContext(ctx, getDlvBin(t), "debug", "--headless",
		"--api-version=2", "--accept-multiclient", "--listen", listenAddr, fixturePath)
	server_out = saveOutput{}
	server_err = saveOutput{}
	server.Stdout = &server_out
	server.Stderr = &server_err
	assertNoError(server.Start(), t, "start headless instance")
	waitForServer(t, &server_out, &server_err)

	// Run dlv client until exit or timeout
	client_timeout := 10 * time.Second
	t.Logf("Starting client with timeout %v\n", client_timeout)
	ctx, cancel = context.WithTimeout(context.Background(), client_timeout)
	defer cancel()
	var init_watchexpr string
	if len(expected_events) > 0 {
		init_watchexpr = expected_events[0].Expression
	}
	if initial_watchexpr != nil {
		init_watchexpr = *initial_watchexpr
	}
	init_line := expected_events[0].Line

	event_log := "event_log.csv"
	behavior_map := "behavior_map.csv"
	if os.Getenv("CT_KEEP_CSVS") == "" {
		event_log = filepath.Join(t.TempDir(), event_log)
		behavior_map = filepath.Join(t.TempDir(), behavior_map)
	}

	client := exec.CommandContext(ctx, getClientBin(t),
		"-initial_bp_file="+fixturePath, fmt.Sprintf("-initial_bp_line=%v", init_line),
		"-initial_watchexpr="+init_watchexpr, "-module="+module, fmt.Sprintf("-move_wps=%t", move_wps),
		"-event_log_file="+event_log, "-behavior_map_file="+behavior_map)
	if init_watchexpr == "" {
		client = exec.CommandContext(ctx, getClientBin(t))
	}

	var client_out saveOutput
	var client_err saveOutput
	client.Stdout = &client_out
	client.Stderr = &client_err

	if err := client.Run(); err != nil {
		if err.Error() == "signal: killed" {
			// Can occur with structs test, but not when run outside `go test`
			t.Logf("Test OOM - may cause failure if occurred before end")
		} else {
			t.Fatalf("Client exited with error: %v\n", err.Error())
		}
	}

	checkStderr(t, client_err.savedOutput, server_err.savedOutput)
	checkEvents(t, expected_events, event_log)
	//checkBehaviorMap(t, expected_behavior_map, behavior_map)
}

func checkStderr(t *testing.T, client_err []byte, server_err []byte) {
	// Check for errors during replay
	/*
		if len(server_err) > 0 {
			server_lines := strings.Split(strings.Trim(string(server_err), "\n"), "\n")
			if len(server_lines) == 1 && strings.Contains(server_lines[0], "Listening for remote connections") {
				// normal
			} else {
				t.Fatalf("Delve server errored while client running: %s", server_err)
			}
		}
		if len(client_err) > 0 {
			t.Fatalf("Delve client errored: %s", client_err)
		}
	*/
}

func checkEvents(t *testing.T, expected []ct.Event, event_log string) {
	file, err := os.Open(event_log)
	assertNoError(err, t, "open event log")
	defer file.Close()
	r := csv.NewReader(file)

	_, err = r.Read() // read header
	assertNoError(err, t, "read header")

	events, err := ct.ReadEventLog(event_log)
	assertNoError(err, t, "read event log")
	// Hits are present in actual but not expected => indices are not 1:1
	expected_i := 0
	for _, actual := range events {
		if actual.EventType == ct.WatchpointSet {
			// Don't know what address to expect (and doesn't matter)
			assertEventsEqual(t, expected[expected_i], actual, fmt.Sprintf("event %v wrong", expected_i), true)
			// Expect mem-param update next (possibly with hits interspersed) => fill in addresses
			offset := 0
			for addr := actual.Address; addr < actual.Address+actual.Size; addr++ {
				expected[expected_i+offset+1].Address = addr
				offset++
			}
		} else if actual.EventType == ct.MemParamMapUpdate {
			assertEventsEqual(t, expected[expected_i], actual, fmt.Sprintf("event %v wrong", expected_i), false)
		} else if actual.EventType == ct.WatchpointHit {
			// Ignore for now. Might be useful to test in some cases
			// (i.e. if hit doesn't cause a new wp to be set in this case, but could in other cases), but
			// annoying to figure out ground truth - whether/how many hits on a line depends on exactly how it compiles.
			expected_i-- // won't advance in expected
		}
		expected_i++
	}
}
func checkBehaviorMap(t *testing.T, expected_events []ct.Event, behavior_map string) {

}

func assertEventsEqual(t testing.TB, expected ct.Event, actual ct.Event, msg string, ignore_addr bool) {
	b := new(bytes.Buffer)
	w := csv.NewWriter(b)
	ct.WriteEvent(nil, w, expected)
	w.Write([]string{})
	ct.WriteEvent(nil, w, actual)

	t.Helper()
	var opt cmp.Option
	if ignore_addr {
		opt = cmp.FilterPath(func(p cmp.Path) bool {
			vx := p.Last().String()
			return vx == ".Address"
		}, cmp.Ignore())
	}

	if diff := cmp.Diff(expected, actual, opt); diff != "" {
		_, file, line, _ := runtime.Caller(1)
		fname := filepath.Base(file)
		t.Fatalf("failed assertion at %s:%d: expected vs actual:\n%v\ndiff %v (%v)\n", fname, line,
			b.String(), diff, msg)
	}
}
