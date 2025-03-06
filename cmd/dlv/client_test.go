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

const module = "test_module"

// Notes:
// Need to build target with fork of go that has allocator changes, so:
// - If run from IDE, IDE needs to be set to use that fork
// - Will build delve, client, and target with that fork of go, so they need to be compatible with it
// (e.g. go 1.20.1 doesn't have max/min builtins)

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
func simpleWatchpointSet(config string, watchexpr string, sz uint64, line int, flow ct.TaintFlow) []ct.Event {
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
	tainting_vals := ct.TaintingVals{
		Params: *set.From([]ct.TaintingParam{tainting_param}),
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
	expected_events := simpleWatchpointSet(config, config, uint64(len(config)), 10, ct.DataFlow)

	// 2. Hit wp in if condition => propagate to maybe_tainted
	expected_events = append(expected_events, ct.Event{
		EventType: ct.WatchpointHit, Size: 6, Expression: config, Line: 16,
	})

	expected_events = append(expected_events,
		simpleWatchpointSet(config, "maybe_tainted", 3, 22, ct.ControlFlow)...)

	fmt.Printf("initial expected: %v\n", expected_events)
	run(t, "control_flow.go", expected_events, nil)
}

// Tests clear when another sw wp still exists on same page
func TestCallAndAssign1(t *testing.T) {
	config := "stack"
	expected_events := simpleWatchpointSet(config, config, uint64(len(config)), 31, ct.DataFlow)
	run(t, "call_assign_1.go", expected_events, nil)
}

func TestCallAndAssign2(t *testing.T) {
	expected_events := []ct.Event{}
	run(t, "call_assign_2.go", expected_events, nil)
}

func TestStrings(t *testing.T) {
	expected_events := []ct.Event{}
	run(t, "strings.go", expected_events, nil)
}

func TestSliceRangeBuiltins(t *testing.T) {
	expected_events := []ct.Event{}
	// Client sets initial watch on conf.search => server sets wp on both strings
	initial_watchexpr := "conf.search"
	run(t, "slice_range_builtins.go", expected_events, &initial_watchexpr)
}

// Slice of slices, array of slices/strings (slice of strings is in TestSliceRangeBuiltins)
// Note that this test checks the watchexpr, so it's important how the server chooses to set it -
// does so when (t *Target) SetWatchpoint calls SetWatchpointNoEval instead of telling the
// Debugger to recurse (i.e. get to a string or slice/array of non-references)
func TestReferenceElems(t *testing.T) {
	dir := "reference_elems/"

	// Array of strings => set on each string
	expected_events := []ct.Event{}
	initial_watchexpr := "arr_strs"
	run(t, dir+"arr_strs.go", expected_events, &initial_watchexpr)

	// Array of slices => set on each slice's strings
	expected_events = []ct.Event{}
	initial_watchexpr = "arr_slices"
	run(t, dir+"arr_slices.go", expected_events, &initial_watchexpr)

	// Slice of slices => set on each inner slice's strings
	expected_events = []ct.Event{}
	initial_watchexpr = "slice_slices"
	run(t, dir+"slice_slices.go", expected_events, &initial_watchexpr)
}

func TestMethods(t *testing.T) {
	expected_events := []ct.Event{}

	run(t, "methods.go", expected_events, nil)
}

func TestFuncLitGoRoutine(t *testing.T) {
	// Compiler uses same memory for chars of both fqdn strings,
	// so only expect wp for chars on 13
	expected_events := []ct.Event{}
	run(t, "funclit_goroutine.go", expected_events, nil)
}

func TestMultiRound(t *testing.T) {
	expected_events := []ct.Event{}

	run(t, "multiround.go", expected_events, nil)
}

func TestRuntimeHits(t *testing.T) {
	expected_events := []ct.Event{
		// uses same backing array for name and name_callee, but n.Data and n_caller.Data each have their own
	}

	run(t, "runtime_hits.go", expected_events, nil)
}

func TestCasts(t *testing.T) {
	expected_events := []ct.Event{}

	run(t, "casts.go", expected_events, nil)
}

func TestNetworkSend(t *testing.T) {
	// XXX I think can replace by splitting network_recv in two
	expected_events := []ct.Event{}

	run(t, "network_send.go", expected_events, nil)
}
func TestNetworkRecv(t *testing.T) {
	expected_events := []ct.Event{
		// XXX need way to test m-c map update that has a behavior as value (not param)
	}

	run(t, "network_recv.go", expected_events, nil)
}
func TestStructs(t *testing.T) {
	expected_events := []ct.Event{}
	run(t, "structs.go", expected_events, nil)
}

func TestAllocatorHTTP(t *testing.T) {
	expected_events := []ct.Event{}

	run(t, "allocator_http.go", expected_events, nil)
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

// Expect to set watchpoints for watchexprs on corresponding lines
// Client's initial watchexpr is one in the first expected_log,
// unless initial_watchexpr is passed
func run(t *testing.T, testfile string, expected_events []ct.Event, initial_watchexpr *string) {
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

	event_log := filepath.Join(t.TempDir(), "event_log.csv")
	behavior_map := filepath.Join(t.TempDir(), "behavior_map.csv")
	client := exec.CommandContext(ctx, getClientBin(t),
		"-initial_bp_file="+fixturePath, fmt.Sprintf("-initial_bp_line=%v", init_line),
		"-initial_watchexpr="+init_watchexpr, "-module="+module, "-move_wps=false",
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
	for i, actual := range events {
		if actual.EventType == ct.WatchpointSet {
			// Don't know what address to expect (and doesn't matter)
			assertEventsEqual(t, expected[i], actual, fmt.Sprintf("event %v wrong", i), true)
			// Expect mem-param update next => fill in addresses
			offset := 0
			for addr := actual.Address; addr < actual.Address+actual.Size; addr++ {
				expected[i+offset+1].Address = addr
				offset++
			}
		} else if actual.EventType == ct.MemParamMapUpdate {
			assertEventsEqual(t, expected[i], actual, fmt.Sprintf("event %v wrong", i), false)
		} else if actual.EventType == ct.WatchpointHit {
			// Don't know what address to expect (and doesn't matter)
			assertEventsEqual(t, expected[i], actual, fmt.Sprintf("event %v wrong", i), true)
		}
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
