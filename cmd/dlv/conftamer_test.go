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
	// Message events (and corresponding map updates) are always on syscall bp hits: runtime/internal/syscall.Syscall6 - line 30
	syscall_entry_line = 30
	// Name of buf param in syscall.write
	syscall_recv_buf = "p"
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

// If config passed: config.Initial_watchexpr taints the entire watchpoint region (specified by watchexpr/sz/line).
// If additional taint is passed, add that.
// Return resulting watchpoint set and mem-param update events.
func watchpointSet(config *ct.Config, watchexpr string, sz uint64, line int, flow ct.TaintFlow,
	extra_tainting_param *ct.TaintingParam, extra_tainting_behavior *ct.TaintingBehavior) []ct.Event {
	events := []ct.Event{}
	events = append(events, ct.Event{
		EventType:  ct.WatchpointSet,
		Size:       sz,
		Expression: watchexpr,
		Line:       line,
	})

	tainting_params := set.New[ct.TaintingParam](0)

	if config != nil {
		tainting_param := ct.TaintingParam{
			Module: config.Module,
			Param:  config.Initial_watchexpr,
			Flow:   flow,
		}
		tainting_params.Insert(tainting_param)
	}
	if extra_tainting_param != nil {
		tainting_params.Insert(*extra_tainting_param)
	}

	for offset := uint64(0); offset < sz; offset++ {
		tainting_behaviors := set.New[ct.TaintingBehavior](0)
		if extra_tainting_behavior != nil {
			// M-c entry is tainted by corresponding received message offset
			tainting_behavior := *extra_tainting_behavior
			tainting_behavior.Behavior.Offset = offset
			tainting_behaviors.Insert(tainting_behavior)
		}

		tainting_vals := ct.TaintingVals{
			Params:    *tainting_params,
			Behaviors: *tainting_behaviors,
		}
		events = append(events, ct.Event{
			// run() will fill in address from wp set
			EventType: ct.MemParamMapUpdate, Size: 1, TaintingVals: &tainting_vals, Line: line,
		})
	}
	return events
}

func Config(testfile string, initial_watchexpr string, initial_line int) ct.Config {
	c := ct.Config{
		Initial_bp_file:       testfile,
		Initial_bp_line:       initial_line,
		Initial_watchexpr:     initial_watchexpr,
		Module:                "test_module",
		Event_log_filename:    "event_log.csv",
		Behavior_map_filename: "behavior_map.csv",
		Server_endpoint:       "localhost:4040",
	}
	return c
}

func TestControlFlow(t *testing.T) {
	// 1. Set wp for config
	initial_line := 10
	config := Config("control_flow.go", "config", initial_line)

	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(len(config.Initial_watchexpr)), initial_line, ct.DataFlow, nil, nil)

	// 2. Hit wp in if condition => propagate to maybe_tainted
	expected_events = append(expected_events,
		watchpointSet(&config, "maybe_tainted", 3, 18, ct.ControlFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "maybe_tainted_2", 1, 21, ct.ControlFlow, nil, nil)...)

	dataflow_taint := ct.TaintingParam{
		Module: config.Module,
		Param:  config.Initial_watchexpr,
		Flow:   ct.DataFlow,
	}
	expected_events = append(expected_events,
		watchpointSet(&config, "regular", 1, 22, ct.ControlFlow, &dataflow_taint, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "maybe_tainted_3", 1, 31, ct.ControlFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "maybe_tainted_4", 1, 38, ct.ControlFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "i", 1, 39, ct.ControlFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "j", 1, 40, ct.DataFlow, nil, nil)...)

	run(t, config, expected_events)
}

// Tests clear when another sw wp still exists on same page
func TestCallAndAssign1(t *testing.T) {
	initial_line := 31
	config := Config("call_assign_1.go", "stack", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(8), initial_line, ct.DataFlow, nil, nil)

	expected_events = append(expected_events,
		watchpointSet(&config, "spacer", uint64(8), 35, ct.DataFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "tainted_param", uint64(8), 15, ct.DataFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "tainted_param_2", uint64(8), 21, ct.DataFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "y", uint64(8), 42, ct.DataFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "z", uint64(8), 46, ct.DataFlow, nil, nil)...)

	run(t, config, expected_events)
}

func TestCallAndAssign2(t *testing.T) {
	initial_line := 19
	config := Config("call_assign_2.go", "stack", initial_line)

	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(8), initial_line, ct.DataFlow, nil, nil)

	expected_events = append(expected_events,
		watchpointSet(&config, "tainted_param_2", uint64(8), 10, ct.DataFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "a", uint64(8), 22, ct.DataFlow, nil, nil)...)

	run(t, config, expected_events)
}

func TestStrings(t *testing.T) {
	initial_line := 15
	config := Config("strings.go", "s", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(2), initial_line, ct.DataFlow, nil, nil)

	expected_events = append(expected_events,
		watchpointSet(&config, "s2", uint64(6), 16, ct.DataFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "i", uint64(1), 19, ct.DataFlow, nil, nil)...)

	run(t, config, expected_events)
}

func TestSliceRangeBuiltins(t *testing.T) {
	// Client sets initial watch on conf.search => server sets wp on both strings
	initial_line := 14
	config := Config("slice_range_builtins.go", "conf.search", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr+"[0]", uint64(2), initial_line, ct.DataFlow, nil, nil)
	expected_events = append(expected_events,
		watchpointSet(&config, config.Initial_watchexpr+"[1]", uint64(5), 14, ct.DataFlow, nil, nil)...)
	expected_events = append(expected_events,
		watchpointSet(&config, "names[0]", uint64(9+2), 22, ct.DataFlow, nil, nil)...)
	expected_events = append(expected_events,
		watchpointSet(&config, "names[1]", uint64(9+5), 22, ct.DataFlow, nil, nil)...)

	run(t, config, expected_events)
}

// Slice of slices, array of slices/strings (slice of strings is in TestSliceRangeBuiltins)
// Note that this test checks the watchexpr, so it's important how the server chooses to set it -
// does so when (t *Target) SetWatchpoint calls SetWatchpointNoEval instead of telling the
// Debugger to recurse (i.e. get to a string or slice/array of non-references)
func TestReferenceElems(t *testing.T) {
	dir := "reference_elems/"

	initial_line := 10
	config := Config(dir+"arr_strs.go", "arr_strs", initial_line)
	// Array of strings => set on each string
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr+"[0]", uint64(2), initial_line, ct.DataFlow, nil, nil)
	expected_events = append(expected_events,
		watchpointSet(&config, config.Initial_watchexpr+"[1]", uint64(5), initial_line, ct.DataFlow, nil, nil)...)
	run(t, config, expected_events)

	// Array of slices => set on each slice's strings
	initial_line = 12
	config = Config(dir+"arr_slices.go", "arr_slices", initial_line)
	expected_events =
		watchpointSet(&config, config.Initial_watchexpr+"[0][0]", uint64(2), initial_line, ct.DataFlow, nil, nil)
	expected_events = append(expected_events,
		watchpointSet(&config, config.Initial_watchexpr+"[0][1]", uint64(5), initial_line, ct.DataFlow, nil, nil)...)
	expected_events = append(expected_events,
		watchpointSet(&config, config.Initial_watchexpr+"[1][0]", uint64(3), initial_line, ct.DataFlow, nil, nil)...)
	expected_events = append(expected_events,
		watchpointSet(&config, config.Initial_watchexpr+"[1][1]", uint64(4), initial_line, ct.DataFlow, nil, nil)...)
	run(t, config, expected_events)

	// Slice of slices => set on each inner slice's strings
	config = Config(dir+"slice_slices.go", "slice_slices", initial_line)
	expected_events =
		watchpointSet(&config, config.Initial_watchexpr+"[0][0]", uint64(2), initial_line, ct.DataFlow, nil, nil)
	expected_events = append(expected_events,
		watchpointSet(&config, config.Initial_watchexpr+"[0][1]", uint64(5), initial_line, ct.DataFlow, nil, nil)...)
	expected_events = append(expected_events,
		watchpointSet(&config, config.Initial_watchexpr+"[1][0]", uint64(3), initial_line, ct.DataFlow, nil, nil)...)
	expected_events = append(expected_events,
		watchpointSet(&config, config.Initial_watchexpr+"[1][1]", uint64(4), initial_line, ct.DataFlow, nil, nil)...)
	run(t, config, expected_events)
}

func TestMethods(t *testing.T) {
	initial_line := 39
	config := Config("methods.go", "nested.name.Data", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(2), initial_line, ct.DataFlow, nil, nil)

	expected_events = append(expected_events,
		watchpointSet(&config, "recvr_callee.Data", uint64(2), 27, ct.DataFlow, nil, nil)...)

	run(t, config, expected_events)
}

func TestFuncLitGoRoutine(t *testing.T) {
	// Compiler uses same memory for chars of both fqdn strings,
	// so only expect wp for chars on 13
	initial_line := 14
	config := Config("funclit_goroutine.go", "fqdn", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(4), initial_line, ct.DataFlow, nil, nil)
	run(t, config, expected_events)
}

func TestMultiRound(t *testing.T) {
	initial_line := 11
	config := Config("multiround.go", "vars[0]", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(8), initial_line, ct.DataFlow, nil, nil)

	for i := 0; i < 5; i++ {
		expected_events = append(expected_events,
			watchpointSet(&config, "vars[i]", uint64(8), 16, ct.DataFlow, nil, nil)...)
	}

	run(t, config, expected_events)
}

func TestRuntimeHits(t *testing.T) {
	initial_line := 21
	config := Config("runtime_hits.go", "name", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(2), initial_line, ct.DataFlow, nil, nil)
	// uses same backing array for name and name_callee, but n.Data and n_caller.Data each have their own

	expected_events = append(expected_events,
		watchpointSet(&config, "n.Data[:]", uint64(255), 16, ct.DataFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "n_caller.Data", uint64(255), 22, ct.DataFlow, nil, nil)...)

	run(t, config, expected_events)
}

func TestCasts(t *testing.T) {
	initial_line := 11
	config := Config("casts.go", "x", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(8), initial_line, ct.DataFlow, nil, nil)

	expected_events = append(expected_events,
		watchpointSet(&config, "y", uint64(8), 13, ct.DataFlow, nil, nil)...)

	run(t, config, expected_events)
}

func messageSend(sent_msg ct.BehaviorValue, config ct.Config, sz uint64, taint_start uint64, taint_end uint64) []ct.Event {
	tainting_params := set.From([]ct.TaintingParam{
		{
			Module: config.Module,
			Param:  config.Initial_watchexpr,
			Flow:   ct.DataFlow,
		},
	},
	)
	tainting_vals := ct.TaintingVals{
		Params: *tainting_params,
	}
	events := []ct.Event{
		{EventType: ct.MessageSend, Size: sz, Behavior: &sent_msg, Line: syscall_entry_line},
	}
	// update behavior map for tainted offsets
	for offset := taint_start; offset < taint_end; offset++ {
		msg := sent_msg // gets different address every iter
		msg.Offset = offset
		events = append(events, ct.Event{
			EventType: ct.BehaviorMapUpdate, Size: 1, Behavior: &msg, TaintingVals: &tainting_vals, Line: syscall_entry_line},
		)
	}

	return events
}

func messageRecv(recvd_msg ct.TaintingBehavior, msg_bufsz uint64) []ct.Event {
	// Address to be filled in
	events := []ct.Event{
		{EventType: ct.MessageRecv, Size: msg_bufsz, Behavior: &recvd_msg.Behavior, Line: syscall_entry_line},
	}
	// Set watchpoint on msg buf and update m-c map
	events = append(events,
		watchpointSet(nil, syscall_recv_buf, msg_bufsz, syscall_entry_line, ct.DataFlow, nil, &recvd_msg)...)

	return events
}

func TestNetworkMessages(t *testing.T) {
	// SENDER
	initial_line := 34
	config := Config("behavior_client.go", "config[1]", initial_line)
	config.Module = "send_module"
	config.Event_log_filename = config.Module + "_event_log.csv"
	config.Behavior_map_filename = config.Module + "_behavior_map.csv"

	client_endpoint := "127.0.0.1:5050"
	server_endpoint := "127.0.0.1:6060"
	sent_msg := ct.BehaviorValue{
		Send_endpoint: client_endpoint,
		Recv_endpoint: server_endpoint,
		Transport:     "tcp",
		Send_module:   config.Module,
	}
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(1), initial_line, ct.DataFlow, nil, nil)

	expected_events = append(expected_events, messageSend(sent_msg, config, 6, 1, 2)...)
	go run(t, config, expected_events)

	// RECEIVER
	config = Config("behavior_server.go", "", 0)
	config.Module = "recv_module"
	config.Event_log_filename = config.Module + "_event_log.csv"
	config.Behavior_map_filename = config.Module + "_behavior_map.csv"
	config.Server_endpoint = "localhost:4041"

	recvd_msg := sent_msg
	recvd_msg.Send_module = "" // receiver doesn't know send module
	tainting_behavior := ct.TaintingBehavior{
		Behavior: recvd_msg,
		Flow:     ct.DataFlow,
	}
	expected_events = messageRecv(tainting_behavior, 3)

	expected_events = append(expected_events,
		watchpointSet(nil, "msg_copy", uint64(1), 33, ct.DataFlow, nil, &tainting_behavior)...)

	run(t, config, expected_events)
}

func TestStructs(t *testing.T) {
	initial_line := 26
	config := Config("structs.go", "arr", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(2), initial_line, ct.DataFlow, nil, nil)

	expected_events = append(expected_events,
		watchpointSet(&config, "struct_lit.Data", uint64(2), 27, ct.DataFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "s.Data", uint64(2), 29, ct.DataFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "s_callee.Data", uint64(2), 20, ct.DataFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "s_caller.Data", uint64(2), 31, ct.DataFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "multiline_lit.Data", uint64(2), 36, ct.DataFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "nested.name.Data", uint64(2), 41, ct.DataFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "nested2.name.Data", uint64(2), 44, ct.DataFlow, nil, nil)...)

	run(t, config, expected_events)
}

func TestAllocatorHTTP(t *testing.T) {
	initial_line := 27
	config := Config("allocator_http.go", "*ptr", initial_line)
	config.Move_wps = true
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(8), initial_line, ct.DataFlow, nil, nil)

	expected_events = append(expected_events,
		watchpointSet(&config, "x", uint64(8), 31, ct.DataFlow, nil, nil)...)

	run(t, config, expected_events)
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

// Start a dlv server and client for a module, wait for client to exit/timeout.
// Note this may be called concurrently for multiple modules.
// TODO (minor) prefix log msgs with module to make clearer for tests that run multiple modules
func run(t *testing.T, config ct.Config, expected_events []ct.Event) {
	// Set up config
	config.Initial_bp_file = filepath.Join(protest.FindFixturesDir(), "conftamer", config.Initial_bp_file)
	config.Initial_bp_line = expected_events[0].Line

	if os.Getenv("CT_KEEP_CSVS") == "" {
		event_log := filepath.Join(t.TempDir(), config.Event_log_filename)
		behavior_map := filepath.Join(t.TempDir(), config.Behavior_map_filename)
		config.Event_log_filename = event_log
		config.Behavior_map_filename = behavior_map
	}

	config_file := filepath.Join(t.TempDir(), "client_config.yml")
	ct.SaveConfig(config_file, config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start dlv server
	var server_out saveOutput
	var server_err saveOutput

	server := exec.CommandContext(ctx, getDlvBin(t), "debug", "--headless",
		"--api-version=2", "--accept-multiclient", "--listen", config.Server_endpoint, config.Initial_bp_file)
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

	client := exec.CommandContext(ctx, getClientBin(t), "-config="+config_file)

	var client_out saveOutput
	var client_err saveOutput
	client.Stdout = &client_out
	client.Stderr = &client_err

	if err := client.Run(); err != nil {
		if err.Error() == "signal: killed" {
			// Can occur with some tests, but not when run outside `go test`
			t.Logf("Test OOM - may cause failure if occurred before end")
		} else {
			t.Logf("Client exited with error: %v\n", err.Error())
			t.Fail()
		}
	}

	checkStderr(t, client_err.savedOutput, server_err.savedOutput)
	checkEvents(t, expected_events, config.Event_log_filename)
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
			// Don't know what watchpoint address to expect - but use it to fill in expected m-c map updates
			assertEventsEqual(t, expected[expected_i], actual, fmt.Sprintf("expected event %v wrong", expected_i), true)

			offset := 0
			for addr := actual.Address; addr < actual.Address+actual.Size; addr++ {
				e := &expected[expected_i+offset+1]
				assertEqual(t, ct.MemParamMapUpdate, e.EventType, fmt.Sprintf("expected m-p update after wp set at event %v", expected_i))
				e.Address = addr
				offset++
			}
		} else if actual.EventType == ct.MessageRecv {
			// Don't know what message recv buffer address to expect - but use it to fill in expected wp set address
			assertEventsEqual(t, expected[expected_i], actual, fmt.Sprintf("expected event %v wrong", expected_i), true)

			expected_wp_set := &expected[expected_i+1]
			assertEqual(t, ct.WatchpointSet, expected_wp_set.EventType, fmt.Sprintf("expected wp set after msg recv at event %v", expected_i))
			expected_wp_set.Address = actual.Address
			actual_wp_set := events[expected_i+1]
			// Check wp set now since above logic will ignore addr
			assertEventsEqual(t, *expected_wp_set, actual_wp_set, fmt.Sprintf("expected event %v wrong", expected_i+1), false)
		} else if actual.EventType == ct.MemParamMapUpdate || actual.EventType == ct.BehaviorMapUpdate {
			assertEventsEqual(t, expected[expected_i], actual, fmt.Sprintf("expected event %v wrong", expected_i), false)
		} else if actual.EventType == ct.MessageSend {
			// Don't know what message send buffer address to expect
			assertEventsEqual(t, expected[expected_i], actual, fmt.Sprintf("expected event %v wrong", expected_i), true)
		} else if actual.EventType == ct.WatchpointHit {
			// Ignore for now. Might be useful to test in some cases
			// (i.e. if hit doesn't cause a new wp to be set in this case, but could in other cases), but
			// annoying to figure out ground truth - whether/how many hits on a line depends on exactly how it compiles.
			expected_i-- // won't advance in expected
		}
		expected_i++
	}
}

// XXX remove?
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
