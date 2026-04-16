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
	"sort"
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
)

// Notes:
// When creating two Event{}s, careful of reusing memory for pointer fields

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

func taintingParam() ct.TaintingParam {
	return ct.TaintingParam{Param: ct.Param{Module: "param_module", Param: "param", File: "file"}, Flow: ct.ControlFlow}
}

func networkmsg() ct.BehaviorValue {
	return ct.BehaviorValue{Offset: 1,
		Behavior_type: ct.NetworkMsg,
		Network_msg:   ct.NetworkMessage{Send_endpoint: "send_endpoint", Recv_endpoint: "recv_endpoint", Transport: "tcp"},
		Send_module:   "send_module"}
}

// Make temporary if applicable
func outputFile(t *testing.T, file string) string {
	if os.Getenv("CT_KEEP_CSVS") == "" {
		return filepath.Join(t.TempDir(), file)
	} else {
		return file
	}
}

// Checks .gv
func checkGraph(t *testing.T, behavior_maps []string, graph_file string, expected_lines []string) {
	graph_file = outputFile(t, graph_file)
	_, err := ct.WriteGraph(graph_file, behavior_maps)
	assertNoError(err, t, "write graph")

	graph, err := os.ReadFile(graph_file)
	assertNoError(err, t, "read graph file")
	lines := strings.Split(string(graph), "\n")
	// order of lines in .gv isn't deterministic
	sort.Strings(expected_lines)
	actual_lines := []string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			actual_lines = append(actual_lines, line)
		}
	}
	sort.Strings(actual_lines)
	assertEqual(t, len(expected_lines), len(actual_lines), "length of graph file")

	for i, line := range actual_lines {
		assertEqual(t, expected_lines[i], strings.TrimSpace(line), fmt.Sprintf("graph %v line wrong", i))
	}
	// Would be nice to check .gv can be rendered (unclear how to call dot from here - neither dot nor /usr/bin/dot finds the executable)
}

func TestWriteGraph(t *testing.T) {
	send_param := taintingParam()
	send_behavior := networkmsg()
	send_tainting_vals := ct.MakeTaintingVals(&send_param, nil)

	send_behavior_map := ct.BehaviorMap{send_behavior: send_tainting_vals}
	// tainted ones are reachable => should be combined with sender's node
	recv_tainted := send_behavior
	recv_tainted.Send_module = ""
	recv_tainted.Recv_module = "recv_module"
	// untainted ones are unreachable => should be removed
	recv_untainted := recv_tainted
	recv_untainted.Offset = recv_tainted.Offset + 1

	send_tainted := ct.BehaviorValue{Offset: 1,
		Behavior_type: ct.NetworkMsg,
		Network_msg:   ct.NetworkMessage{Send_endpoint: "send_endpoint_2", Recv_endpoint: "recv_endpoint_2", Transport: "tcp"},
		Send_module:   "recv_module"}
	send_untainted := send_tainted
	send_untainted.Offset = send_tainted.Offset + 1

	tainting_vals := ct.MakeTaintingVals(nil, &ct.TaintingBehavior{Behavior: recv_tainted, Flow: ct.DataFlow})
	recv_behavior_map := ct.BehaviorMap{send_tainted: tainting_vals, send_untainted: tainting_vals}
	tainting_vals = ct.MakeTaintingVals(nil, &ct.TaintingBehavior{Behavior: recv_untainted, Flow: ct.DataFlow})
	recv_behavior_map[send_untainted] = tainting_vals

	send_file := outputFile(t, "fake_send_map.csv")
	recv_file := outputFile(t, "fake_recv_map.csv")
	assertNoError(ct.WriteBehaviorMap(send_file, send_behavior_map), t, "write")
	assertNoError(ct.WriteBehaviorMap(recv_file, recv_behavior_map), t, "write")

	expected_lines := []string{
		"strict digraph {",
		"\"{ {param_module file param} {0    {  } { }}}\" [  weight=0 ];",
		"\"{ {param_module file param} {0    {  } { }}}\" -> \"{ {  } {1   network message {send_endpoint recv_endpoint tcp} { }}}\" [ EdgeType=\"Control Flow\",  weight=0 ];",
		"\"{ {  } {1   network message {send_endpoint recv_endpoint tcp} { }}}\" [  weight=0 ];",
		"\"{ {  } {1   network message {send_endpoint recv_endpoint tcp} { }}}\" -> \"{ {  } {1   network message {send_endpoint_2 recv_endpoint_2 tcp} { }}}\" [ EdgeType=\"Data Flow\",  weight=0 ];",
		"\"{ {  } {1   network message {send_endpoint_2 recv_endpoint_2 tcp} { }}}\" [  weight=0 ];",
		"}",
	}
	checkGraph(t, []string{send_file, recv_file}, "fake_graph.gv", expected_lines)
}

func readWriteBehaviorMap(t *testing.T, behavior_map ct.BehaviorMap) string {
	file := outputFile(t, "behavior_map.csv")
	assertNoError(ct.WriteBehaviorMap(file, behavior_map), t, "write")
	behavior_map_2, err := ct.ReadBehaviorMap(file)
	assertNoError(err, t, "read")

	// Check equality (and that read/write worked)
	if diff := cmp.Diff(behavior_map, behavior_map_2); diff != "" {
		t.Fatalf("Map before read != after\nDiff: %v\nBefore: %v\nAfter: %v",
			diff, behavior_map, behavior_map_2)
	}
	return file
}

// Check behavior map read/write to file, and equality operations on it
func TestReadWriteBehaviorMap(t *testing.T) {
	tainting_param := taintingParam()
	behavior := networkmsg()
	tainting_behavior := ct.TaintingBehavior{
		Behavior: behavior,
		Flow:     ct.DataFlow,
	}
	tainting_vals := ct.MakeTaintingVals(&tainting_param, &tainting_behavior)
	behavior_map := make(ct.BehaviorMap)
	behavior_map[behavior] = tainting_vals

	readWriteBehaviorMap(t, behavior_map)

	// Check inequality (modify flow for behavior)
	tainting_behavior.Flow = ct.ControlFlow
	tainting_vals = ct.MakeTaintingVals(&tainting_param, &tainting_behavior)

	behavior_map_modified := make(ct.BehaviorMap)
	behavior_map_modified[behavior] = tainting_vals

	if diff := cmp.Diff(behavior_map, behavior_map_modified); diff == "" {
		t.Fatalf("Failed to detect inequality: %v vs %v\n",
			behavior_map, behavior_map_modified)
	}

	// Check empty sets can still marshal/unmarshal
	behavior_map[behavior] = ct.TaintingVals{} // XXX should it be this or NewTaintingValues? (i.e. if empty, has client already created set?)

	readWriteBehaviorMap(t, behavior_map)
}

type TestConfig struct {
	checkDupEvents bool
	useLocalGo     bool
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
		LoggerLevel:           "info",
	}
	return c
}

func TestControlFlow(t *testing.T) {
	// 1. Set wp for config[0]
	initial_line := 10
	config := Config("control_flow.go", "config[0]", initial_line)

	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(1), initial_line, ct.DataFlow, nil, nil)

	// 2. Hit wp in if condition => propagate to maybe_tainted
	expected_events = append(expected_events,
		watchpointSet(&config, "maybe_tainted", 3, 19, ct.ControlFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "maybe_tainted_2", 1, 21, ct.ControlFlow, nil, nil)...)

	dataflow_taint := ct.TaintingParam{
		Param: ct.Param{
			Module: config.Module,
			Param:  config.Initial_watchexpr,
		},
		Flow: ct.DataFlow,
	}
	expected_events = append(expected_events,
		watchpointSet(&config, "regular", 1, 25, ct.ControlFlow, &dataflow_taint, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "maybe_tainted_3", 1, 31, ct.ControlFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "maybe_tainted_4", 1, 35, ct.ControlFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "maybe_tainted_5", 5, 43, ct.ControlFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "i", 1, 48, ct.ControlFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "j", 1, 49, ct.DataFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "x", 8, 61, ct.ControlFlow, nil, nil)...)

	run(t, &config, expected_events, nil)
}

// Tests clear when another sw wp still exists on same page
func TestCallAndAssign1(t *testing.T) {
	initial_line := 32
	config := Config("call_assign_1.go", "stack", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(8), initial_line, ct.DataFlow, nil, nil)

		// next() skips runtime.KeepAlive (although a user breakpoint for it will hit, and it has a statement, and in structs.go it doesn't) - unsure why
	expected_events = append(expected_events,
		watchpointSet(&config, "spacer", uint64(8), 37, ct.DataFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "tainted_param", uint64(8), 15, ct.DataFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "tainted_param_2", uint64(8), 21, ct.DataFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "y", uint64(8), 42, ct.DataFlow, nil, nil)...)

	// Coincidental hit on L38 after ret_untainted is called (for memory preceding stack, but server returns it bc assumes 16B access) =>
	// client re-handles L38, thus re-sets bp on ret_untainted to set wp on its arg
	// Should fix in client eventually - already put a comment there
	expected_events = append(expected_events,
		watchpointSet(&config, "tainted_param", uint64(8), 15, ct.DataFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "z", uint64(8), 46, ct.DataFlow, nil, nil)...)

	// Check dups, since compiler shares memory for callee copy of params (could fix by splitting test)
	run(t, &config, expected_events, &TestConfig{checkDupEvents: true})
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

	run(t, &config, expected_events, nil)
}

func TestStrings(t *testing.T) {
	initial_line := 15
	config := Config("strings.go", "s", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(2), initial_line, ct.DataFlow, nil, nil)

	expected_events = append(expected_events, TestEvent{
		e:        ct.Event{EventType: ct.WatchpointSet, Size: 6, Expression: "s2", Line: 16},
		taint_sz: 2})

	tainting_param := configTaintingParam(&config, ct.DataFlow)
	tainting_vals := ct.TaintingVals{Params: tainting_param}
	// Need to impl strcat support - currently taints first two bytes of s2, but should be last two
	for offset := 0; offset < 2; offset++ {
		expected_events = append(expected_events, TestEvent{
			e: ct.Event{EventType: ct.MemParamMapUpdate, Size: 1, TaintingVals: &tainting_vals, Line: 16}})
	}

	expected_events = append(expected_events,
		watchpointSet(&config, "i", uint64(1), 19, ct.DataFlow, nil, nil)...)

	run(t, &config, expected_events, nil)
}

// Also tests append w/ reference elems
func TestSliceRangeBuiltins(t *testing.T) {
	// Client sets initial watch on conf.search => server sets wp on both strings
	initial_line := 14
	config := Config("slice_range_builtins.go", "conf.search", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr+"[0]", uint64(2), initial_line, ct.DataFlow, nil, nil)
	expected_events = append(expected_events,
		watchpointSet(&config, config.Initial_watchexpr+"[1]", uint64(5), initial_line, ct.DataFlow, nil, nil)...)
	// Need to impl strcat support - currently taints first len(suffix) bytes of each str, but should be last ones
	for i := 0; i < 2; i++ {
		suffix := "hi"
		names_i := 0
		if i == 1 {
			suffix = "hello"
			names_i = 1
		}
		expected_events = append(expected_events,
			watchpointSet(&config, fmt.Sprintf("names[%v]", names_i), uint64(len(suffix)), 16, ct.DataFlow, nil, nil)...)
		// set wp on entire names[i], only taint first len(suffix) B => fix wp sz and taint size
		expected_events[len(expected_events)-len(suffix)-1].taint_sz = uint64(len(suffix))
		expected_events[len(expected_events)-len(suffix)-1].e.Size = uint64(len("localhost") + len(suffix))
	}

	run(t, &config, expected_events, nil)
}

func TestAppend(t *testing.T) {
	initial_line := 11
	config := Config("append.go", "old", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(16), initial_line, ct.DataFlow, nil, nil)

		// set wp on entire new, only taint new[1] => fix wp sz and taint offset/size
	expected_events = append(expected_events,
		watchpointSet(&config, "new", uint64(8), 13, ct.DataFlow, nil, nil)...)
	expected_events[len(expected_events)-9].taint_offset = 8
	expected_events[len(expected_events)-9].taint_sz = 8
	expected_events[len(expected_events)-9].e.Size = 16

	run(t, &config, expected_events, nil)
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
	run(t, &config, expected_events, nil)

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
	run(t, &config, expected_events, nil)

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
	run(t, &config, expected_events, nil)

	// Slice of struct with one non-reference elem and one slice => set on non-reference elem and slice's elements
	initial_line = 16
	config = Config(dir+"struct_slice.go", "slice_struct_slice", initial_line)
	expected_events =
		watchpointSet(&config, config.Initial_watchexpr+"[0].NonReference", uint64(8), initial_line, ct.DataFlow, nil, nil)
	expected_events = append(expected_events,
		watchpointSet(&config, config.Initial_watchexpr+"[0].Reference", uint64(16), initial_line, ct.DataFlow, nil, nil)...)
	run(t, &config, expected_events, nil)
}

/* Tests propagating from return in tainted branch body,
 * through another return in caller, to another branch body. */
func TestPropagateReturn(t *testing.T) {
	old_go := os.Getenv("CT_TARGET_GO")
	os.Setenv("CT_TARGET_GO", "/usr/local/go") // for slices package
	initial_line := 15
	config := Config("propagate_return.go", "arr", initial_line)
	// Array of strings => set on each string
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr+"[0]", uint64(1), initial_line, ct.DataFlow, nil, nil)
	expected_events = append(expected_events,
		watchpointSet(&config, "x", uint64(8), 17, ct.ControlFlow, nil, nil)...)
	expected_events = append(expected_events,
		watchpointSet(&config, "y", uint64(8), 18, ct.ControlFlow, nil, nil)...)
	run(t, &config, expected_events, nil)
	os.Setenv("CT_TARGET_GO", old_go)
}

func TestMethods(t *testing.T) {
	initial_line := 39
	config := Config("methods.go", "nested.name.Data", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(16), initial_line, ct.DataFlow, nil, nil)

	expected_events = append(expected_events,
		watchpointSet(&config, "recvr_callee.Data", uint64(16), 27, ct.DataFlow, nil, nil)...)

	// Set watchpoint on untainted struct field (since entire struct is passed as recvr), but don't insert it to m-c
	expected_events = append(expected_events, TestEvent{
		e:        ct.Event{EventType: ct.WatchpointSet, Size: uint64(8), Expression: "recvr_callee.fake", Line: 27},
		taint_sz: 0})

	run(t, &config, expected_events, nil)
}

func TestFuncLitGoRoutine(t *testing.T) {
	// Compiler uses same memory for chars of both fqdn strings,
	// so only expect wp for chars on 13
	initial_line := 14
	config := Config("funclit_goroutine.go", "fqdn", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(4), initial_line, ct.DataFlow, nil, nil)
	run(t, &config, expected_events, nil)
}

func TestParseFn(t *testing.T) {
	initial_line := 16
	config := Config("parsefn.go", "s", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(8), initial_line, ct.DataFlow, nil, nil)
	expected_events = append(expected_events,
		watchpointSet(&config, "s_caller", uint64(8), 10, ct.DataFlow, nil, nil)...)
	run(t, &config, expected_events, nil)
}

func TestMultiRound(t *testing.T) {
	initial_line := 11
	config := Config("multiround.go", "vars[0]", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(8), initial_line, ct.DataFlow, nil, nil)

	for i := 0; i < 5; i++ {
		expected_events = append(expected_events,
			watchpointSet(&config, "vars[i]", uint64(8), 15, ct.DataFlow, nil, nil)...)
	}

	run(t, &config, expected_events, nil)
}

func TestRuntimeHits(t *testing.T) {
	initial_line := 21
	config := Config("runtime_hits.go", "name", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(2), initial_line, ct.DataFlow, nil, nil)
	// uses same backing array for name and name_callee, but n.Data and n_caller.Data each have their own

	// Set wp on entire n.Data, but only insert to m-c for the tainted part ("hi") => fix wp sz
	expected_events = append(expected_events,
		watchpointSet(&config, "n.Data[:]", uint64(2), 16, ct.DataFlow, nil, nil)...)
	expected_events[len(expected_events)-3].e.Size = uint64(255)
	expected_events[len(expected_events)-3].taint_sz = uint64(2)

	// Set wp on entire n_caller.Data, but only insert to m-c for the tainted part ("hi") => fix wp sz
	expected_events = append(expected_events,
		watchpointSet(&config, "n_caller.Data", uint64(2), 22, ct.DataFlow, nil, nil)...)
	expected_events[len(expected_events)-3].e.Size = uint64(255)
	expected_events[len(expected_events)-3].taint_sz = uint64(2)

	// Set watchpoint on untainted struct field (since entire struct is assigned to), but don't insert it to m-c
	expected_events = append(expected_events, TestEvent{
		e:        ct.Event{EventType: ct.WatchpointSet, Size: uint64(1), Expression: "n_caller.Length", Line: 22},
		taint_sz: 0})

	run(t, &config, expected_events, nil)
}

func TestCasts(t *testing.T) {
	initial_line := 9
	config := Config("casts.go", "x", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(2), initial_line, ct.DataFlow, nil, nil)

	expected_events = append(expected_events,
		watchpointSet(&config, "y", uint64(2), 11, ct.DataFlow, nil, nil)...)

	run(t, &config, expected_events, nil)
}

func TestCasts2(t *testing.T) {
	initial_line := 18
	config := Config("casts2.go", "x", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(8), initial_line, ct.DataFlow, nil, nil)

	expected_events = append(expected_events,
		watchpointSet(&config, "y", uint64(8), 20, ct.DataFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "z", uint64(8), 22, ct.DataFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "x_callee", uint64(8), 12, ct.DataFlow, nil, nil)...)

	run(t, &config, expected_events, nil)
}

func TestUnmarshalYaml(t *testing.T) {
	initial_line := 17
	config := Config("unmarshal_yaml.go", "data", initial_line)
	config.Taint_flow = ct.DataFlow
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(9), initial_line, ct.DataFlow, nil, nil)
	expected_events = append(expected_events,
		TestEvent{e: ct.Event{EventType: ct.Fake}, tail: 6}) // for each byte in output struct: hit, set, m-c update
	expected_events = append(expected_events,
		watchpointSet(&config, "tainted1", uint64(1), 24, ct.DataFlow, nil, nil)...)
	expected_events = append(expected_events,
		watchpointSet(&config, "tainted2", uint64(1), 27, ct.DataFlow, nil, nil)...)

	run(t, &config, expected_events, nil)
}

func TestMarshalJson(t *testing.T) {
	initial_line := 17
	config := Config("marshal_json.go", "c.AppsRaw", initial_line)
	config.Taint_flow = ct.DataFlow
	// Just check initial and last wp sets
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(4), initial_line, ct.DataFlow, nil, nil)
	expected_events = append(expected_events,
		TestEvent{e: ct.Event{EventType: ct.Fake}, tail: 5}) // one set, four m-c updates

	// set wp on entire buf, only taint offsets 1:5 inclusive => fix wp sz and taint offset/size
	watch_sz := 15
	taint_sz := uint64(4)

	// TODO this assumes go 1.22.4, as does caddy_scan - add a version check
	expected_events = append(expected_events,
		watchpointSet(&config, "buf", taint_sz, 169, ct.DataFlow, nil, nil)...) // encode.go

	watch_event := &expected_events[len(expected_events)-1-int(taint_sz)]
	watch_event.taint_offset = 1
	watch_event.taint_sz = taint_sz
	watch_event.e.Size = uint64(watch_sz)

	// Use new go since this is to help with caddy, which is currently built with new go
	testcfg := TestConfig{useLocalGo: true}
	run(t, &config, expected_events, &testcfg)
}

func TestMapsInterfaces(t *testing.T) {
	// Client requests wp on interface after json.Unmarshal populates it =>
	// Server watches its underlying data
	iface := "unmarshaled"
	keys := []string{"apps", "http", "servers", "hello", "listen", ":2015", "routes", "handle", "handler", "static_response", "body", "Hello, world!"}
	lens := []uint64{}
	for _, k := range keys {
		lens = append(lens, uint64(len(k)))
	}

	exprs := []string{
		"unmarshaled->\"apps\"",
		"unmarshaled[\"apps\"]->\"http\"",
		"unmarshaled[\"apps\"][\"http\"]->\"servers\"",
		"unmarshaled[\"apps\"][\"http\"][\"servers\"]->\"hello\"",
		"unmarshaled[\"apps\"][\"http\"][\"servers\"][\"hello\"]->\"listen\"",
		"unmarshaled[\"apps\"][\"http\"][\"servers\"][\"hello\"][\"listen\"][0]",
		"unmarshaled[\"apps\"][\"http\"][\"servers\"][\"hello\"]->\"routes\"",
		"unmarshaled[\"apps\"][\"http\"][\"servers\"][\"hello\"][\"routes\"][0]->\"handle\"",
		"unmarshaled[\"apps\"][\"http\"][\"servers\"][\"hello\"][\"routes\"][0][\"handle\"][0]->\"handler\"",
		"unmarshaled[\"apps\"][\"http\"][\"servers\"][\"hello\"][\"routes\"][0][\"handle\"][0][\"handler\"]",
		"unmarshaled[\"apps\"][\"http\"][\"servers\"][\"hello\"][\"routes\"][0][\"handle\"][0]->\"body\"",
		"unmarshaled[\"apps\"][\"http\"][\"servers\"][\"hello\"][\"routes\"][0][\"handle\"][0][\"body\"]",
	}

	initial_line := 21
	config := Config("maps_interfaces.go", iface, initial_line)
	expected_events := []TestEvent{}

	for i, expr := range exprs {
		expected_events = append(expected_events,
			watchpointSet(&config, expr, lens[i], initial_line, ct.DataFlow, nil, nil)...)
	}
	run(t, &config, expected_events, nil)
}

// Return TaintingParam corresponding to config.Initial_watchexpr
func configTaintingParam(config *ct.Config, flow ct.TaintFlow) set.Set[ct.TaintingParam] {
	tainting_params := set.New[ct.TaintingParam](0)

	if config != nil {
		tainting_param := ct.TaintingParam{
			Param: ct.Param{
				Module: config.Module,
				Param:  config.Initial_watchexpr,
				// No file, since this is meant for passed-in variables rather than file loads
			},
			Flow: flow,
		}
		tainting_params.Insert(tainting_param)
	}
	return *tainting_params
}

// If config passed: config.Initial_watchexpr taints the entire watchpoint region (specified by watchexpr/sz/line).
// If additional taint is passed, add that to corresponding sz bytes (starting with extra[Offset], for behavior)
// Return resulting watchpoint set and mem-param update events.
func watchpointSet(config *ct.Config, watchexpr string, sz uint64, line int, flow ct.TaintFlow,
	extra_tainting_param *ct.TaintingParam, extra_tainting_behavior *ct.TaintingBehavior) []TestEvent {
	// Watchpoint
	events := []TestEvent{{
		e:        ct.Event{EventType: ct.WatchpointSet, Size: sz, Expression: watchexpr, Line: line},
		taint_sz: sz,
	}}

	tainting_params := configTaintingParam(config, flow)
	if extra_tainting_param != nil {
		tainting_params.Insert(*extra_tainting_param)
	}

	// Map update
	for offset := uint64(0); offset < sz; offset++ {
		tainting_behaviors := set.New[ct.TaintingBehavior](0)
		if extra_tainting_behavior != nil {
			// M-c entry is tainted by corresponding received message offset
			tainting_behavior := *extra_tainting_behavior
			tainting_behavior.Behavior.Offset = extra_tainting_behavior.Behavior.Offset + offset
			tainting_behaviors.Insert(tainting_behavior)
		}

		tainting_vals := ct.TaintingVals{
			Params:    tainting_params,
			Behaviors: *tainting_behaviors,
		}
		events = append(events, TestEvent{
			e: ct.Event{
				// run() will fill in address from wp set
				EventType: ct.MemParamMapUpdate, Size: 1, TaintingVals: &tainting_vals, Line: line,
			}})
	}
	return events
}

// If config passed: config.Initial_watchexpr taints the region of message specified by taint_start:taint_end.
// Msg buf sz is `sz`.
// If extra behavior is passed, add that to corresponding taint_sz bytes of sent message (starting with
// extra[Offset] and send_msg[Offset])
// Return resulting message send and behavior update events.
func messageSend(config *ct.Config, sent_msg ct.BehaviorValue, sz uint64, taint_sz uint64,
	extra_tainting_behavior *ct.TaintingBehavior) []TestEvent {
	sent_taint_start := sent_msg.Offset
	sent_msg.Offset = 0
	// Message send
	events := []TestEvent{{
		e: ct.Event{EventType: ct.MessageSend, Size: sz, Behavior: &sent_msg, Line: syscall_entry_line}},
	}

	// Tainting vals
	tainting_params := configTaintingParam(config, ct.DataFlow)

	// Update behavior map for tainted offsets of sent msg (corresponding offset of extra_tainting_behavior)

	i := uint64(0)
	for sent_offset := sent_taint_start; sent_offset < sent_taint_start+taint_sz; sent_offset++ {
		sent_msg_copy := sent_msg // gets different address every iter
		// XXX make Event fields non-pointer so dn to worry about this in writing tests?
		sent_msg_copy.Offset = sent_offset
		tainting_behaviors := set.New[ct.TaintingBehavior](0)

		if extra_tainting_behavior != nil {
			recvd_msg := *extra_tainting_behavior
			recvd_msg.Behavior.Offset = extra_tainting_behavior.Behavior.Offset + i
			tainting_behaviors.Insert(recvd_msg)
		}
		tainting_vals := ct.TaintingVals{
			Params:    tainting_params,
			Behaviors: *tainting_behaviors,
		}
		events = append(events, TestEvent{
			e: ct.Event{EventType: ct.BehaviorMapUpdate, Size: 1, Behavior: &sent_msg_copy, TaintingVals: &tainting_vals, Line: syscall_entry_line}},
		)
		i++
	}

	return events
}

func messageRecv(recvd_msg ct.TaintingBehavior, msg_bufsz uint64) []TestEvent {
	// Address to be filled in
	events := []TestEvent{{
		e: ct.Event{EventType: ct.MessageRecv, Size: msg_bufsz, Behavior: &recvd_msg.Behavior, Line: syscall_entry_line}},
	}
	// Set watchpoint on msg buf and update m-c map
	events = append(events,
		watchpointSet(nil, ct.SyscallRecvBuf, msg_bufsz, syscall_entry_line, ct.DataFlow, nil, &recvd_msg)...)

	return events
}

// Also tests copy builtin
func TestLoadConfigParam(t *testing.T) {
	// Write a config file, tell dlv where it is
	config_params := []byte("param1\nparam2\n")
	target_config_file := filepath.Join(t.TempDir(), "target_config.txt")
	assertNoError(os.WriteFile(target_config_file, config_params, 0666), t, "WriteFile")
	dlv_config_path := t.TempDir()
	assertNoError(os.MkdirAll(dlv_config_path+"/dlv", 0770), t, "Mkdir")
	dlv_config_file := filepath.Join(dlv_config_path, "dlv", "config.yml")
	dlv_config := fmt.Sprintf("target-config-files: [%v]", target_config_file)
	assertNoError(os.WriteFile(dlv_config_file, []byte(dlv_config), 0666), t, "WriteFile")
	os.Setenv("XDG_CONFIG_HOME", dlv_config_path)

	config := Config("load_config_param.go", "", 0)
	tainting_param := ct.TaintingParam{
		Param: ct.Param{
			Module: config.Module,
			File:   target_config_file,
		},
		Flow: ct.DataFlow,
	}

	tainting_vals := ct.MakeTaintingVals(&tainting_param, nil)

	// Two read syscalls: one reads whole file, second advances buf pointer and reads nothing (EOF)
	// First read
	readbufsz := uint64(512) // ReadFile uses buf of this size (0x200) for smaller files
	config_load := ct.Event{
		EventType:    ct.ConfigLoad,
		Size:         readbufsz,
		TaintingVals: &tainting_vals,
		Line:         syscall_entry_line,
	}
	expected_events := []TestEvent{{e: config_load}}
	expected_events = append(expected_events,
		watchpointSet(nil, ct.SyscallRecvBuf, readbufsz, syscall_entry_line, ct.DataFlow, &tainting_param, nil)...)

	// Second read
	readbufsz -= uint64(len(config_params))
	config_load.Size = readbufsz
	expected_events = append(expected_events, TestEvent{e: config_load})
	expected_events = append(expected_events,
		watchpointSet(nil, ct.SyscallRecvBuf, readbufsz, syscall_entry_line, ct.DataFlow, &tainting_param, nil)...)

	// bytes2
	sz := uint64(13)
	expected_events = append(expected_events, TestEvent{
		e:        ct.Event{EventType: ct.WatchpointSet, Size: sz, Expression: "bytes2", Line: 24},
		taint_sz: sz})

	param := "param1"
	tainting_param.Param.Param = param
	col := 0
	for offset := uint64(0); offset < sz; offset++ {
		tp := ct.TaintingParam{
			Param: ct.Param{
				Module: config.Module,
				File:   target_config_file,
			},
			Flow: ct.DataFlow,
		}
		if offset == 6 {
			// \n
			tp.Param.Param = ""
			col = 0
		} else if offset < 6 {
			tp.Param.Param = "param1"
			tp.Param.Column_number = col
			tp.Param.Row_number = 0
			col++
		} else if offset > 6 {
			tp.Param.Param = "param2"
			tp.Param.Column_number = col
			tp.Param.Row_number = 1
			col++
		}
		tainting_vals := ct.MakeTaintingVals(&tp, nil)
		expected_events = append(expected_events, TestEvent{
			e: ct.Event{EventType: ct.MemParamMapUpdate, Size: 1, TaintingVals: &tainting_vals, Line: 24},
		})
	}

	// param1_var
	param = "param1"
	tainting_param.Param.Param = param

	expected_events = append(expected_events, TestEvent{
		e:        ct.Event{EventType: ct.WatchpointSet, Size: uint64(len(param)), Expression: "param1_var", Line: 26},
		taint_sz: uint64(len(param)),
	})

	for i := 0; i < len(param); i++ {
		tp := ct.TaintingParam{
			Param: ct.Param{
				Module:        config.Module,
				File:          target_config_file,
				Param:         "param1",
				Row_number:    0,
				Column_number: i, // 0-indexed
			},
			Flow: ct.DataFlow,
		}
		tv := ct.MakeTaintingVals(&tp, nil)
		expected_events = append(expected_events, TestEvent{
			e: ct.Event{
				EventType:    ct.MemParamMapUpdate,
				Size:         1,
				TaintingVals: &tv,
				Line:         26,
			},
		})
	}
	// Not using watchpoint set because it assumes that the params are unique (b4 adding col/line number)

	//expected_events = append(expected_events,
	// watchpointSet(nil, "param1_var", uint64(len(param)), 26, ct.DataFlow, &tainting_param, nil)...)

	// The usual syntax for passing args from dlv to target doesn't work in test
	os.Setenv("config", target_config_file)
	run(t, &config, expected_events, &TestConfig{checkDupEvents: true})
}

// Also tests copy builtin
func TestLoadConfigParamJSON(t *testing.T) {
	// Write a config file, tell dlv where it is
	config_params := []byte(`{"param1": 1}`)
	target_config_file := filepath.Join(t.TempDir(), "target_config.json")
	assertNoError(os.WriteFile(target_config_file, config_params, 0666), t, "WriteFile")
	dlv_config_path := t.TempDir()
	assertNoError(os.MkdirAll(dlv_config_path+"/dlv", 0770), t, "Mkdir")
	dlv_config_file := filepath.Join(dlv_config_path, "dlv", "config.yml")
	dlv_config := fmt.Sprintf("target-config-files: [%v]", target_config_file)
	assertNoError(os.WriteFile(dlv_config_file, []byte(dlv_config), 0666), t, "WriteFile")
	os.Setenv("XDG_CONFIG_HOME", dlv_config_path)

	config := Config("load_config_param_JSON.go", "", 0)
	config.Config_file_type = 1
	//config.LoggerLevel = "Debug"

	tainting_param := ct.TaintingParam{
		Param: ct.Param{
			Module: config.Module,
			File:   target_config_file,
		},
		Flow: ct.DataFlow,
	}

	tainting_vals := ct.MakeTaintingVals(&tainting_param, nil)

	// Two read syscalls: one reads whole file, second advances buf pointer and reads nothing (EOF)
	// First read
	readbufsz := uint64(512) // ReadFile uses buf of this size (0x200) for smaller files
	config_load := ct.Event{
		EventType:    ct.ConfigLoad,
		Size:         readbufsz,
		TaintingVals: &tainting_vals,
		Line:         syscall_entry_line,
	}
	expected_events := []TestEvent{{e: config_load}}
	expected_events = append(expected_events,
		watchpointSet(nil, ct.SyscallRecvBuf, readbufsz, syscall_entry_line, ct.DataFlow, &tainting_param, nil)...)

	// Second read
	readbufsz -= uint64(len(config_params))
	config_load.Size = readbufsz
	expected_events = append(expected_events, TestEvent{e: config_load})
	expected_events = append(expected_events,
		watchpointSet(nil, ct.SyscallRecvBuf, readbufsz, syscall_entry_line, ct.DataFlow, &tainting_param, nil)...)

	// bytes2
	val := `{"param1": 1}`

	sz := uint64(len(val))
	expected_events = append(expected_events, TestEvent{
		e:        ct.Event{EventType: ct.WatchpointSet, Size: sz, Expression: "bytes2", Line: 24},
		taint_sz: sz})

	empty_tainting_param := tainting_param
	empty_tainting_param.Param.Param = ""
	empty_tainting_vals := ct.MakeTaintingVals(&empty_tainting_param, nil)

	param_tainting_param := tainting_param
	param_tainting_param.Param.Param = "param1"

	// chars: {"
	for i := 0; i <= 1; i++ {
		expected_events = append(expected_events, TestEvent{
			e: ct.Event{EventType: ct.MemParamMapUpdate, Size: 1, TaintingVals: &empty_tainting_vals, Line: 24},
		})
	}
	// chars: param1
	for offset := 2; offset <= 7; offset++ {
		param_tainting_param.Param.Column_number = offset
		param_tainting_param.Param.Row_number = 0

		param_tainting_vals := ct.MakeTaintingVals(&param_tainting_param, nil)
		expected_events = append(expected_events, TestEvent{
			e: ct.Event{EventType: ct.MemParamMapUpdate, Size: 1, TaintingVals: &param_tainting_vals, Line: 24},
		})
	}
	// chars: ":
	for i := 8; i <= 10; i++ {
		expected_events = append(expected_events, TestEvent{
			e: ct.Event{EventType: ct.MemParamMapUpdate, Size: 1, TaintingVals: &empty_tainting_vals, Line: 24},
		})
	}
	param_tainting_param.Param.Column_number = 11
	param_tainting_param.Param.Row_number = 0

	param_tainting_vals := ct.MakeTaintingVals(&param_tainting_param, nil)
	expected_events = append(expected_events, TestEvent{
		e: ct.Event{EventType: ct.MemParamMapUpdate, Size: 1, TaintingVals: &param_tainting_vals, Line: 24},
	})

	expected_events = append(expected_events, TestEvent{
		e: ct.Event{EventType: ct.MemParamMapUpdate, Size: 1, TaintingVals: &empty_tainting_vals, Line: 24},
	})

	// The usual syntax for passing args from dlv to target doesn't work in test
	os.Setenv("config", target_config_file)
	run(t, &config, expected_events, &TestConfig{checkDupEvents: true})
}

func TestLoadConfigParamJSONComplex(t *testing.T) {
	// Write a config file, tell dlv where it is
	config_params := []byte(`{"apps":{"listen":[":2015",":2016"]}}`)
	target_config_file := filepath.Join(t.TempDir(), "target_config.json")
	assertNoError(os.WriteFile(target_config_file, config_params, 0666), t, "WriteFile")
	dlv_config_path := t.TempDir()
	assertNoError(os.MkdirAll(dlv_config_path+"/dlv", 0770), t, "Mkdir")
	dlv_config_file := filepath.Join(dlv_config_path, "dlv", "config.yml")
	dlv_config := fmt.Sprintf("target-config-files: [%v]", target_config_file)
	assertNoError(os.WriteFile(dlv_config_file, []byte(dlv_config), 0666), t, "WriteFile")
	os.Setenv("XDG_CONFIG_HOME", dlv_config_path)

	config := Config("load_config_param_complex_JSON.go", "", 0)
	config.Config_file_type = 1
	//config.LoggerLevel = "Debug"

	tainting_param := ct.TaintingParam{
		Param: ct.Param{
			Module: config.Module,
			File:   target_config_file,
		},
		Flow: ct.DataFlow,
	}

	tainting_vals := ct.MakeTaintingVals(&tainting_param, nil)

	// Two read syscalls: one reads whole file, second advances buf pointer and reads nothing (EOF)
	// First read
	readbufsz := uint64(512) // ReadFile uses buf of this size (0x200) for smaller files
	config_load := ct.Event{
		EventType:    ct.ConfigLoad,
		Size:         readbufsz,
		TaintingVals: &tainting_vals,
		Line:         syscall_entry_line,
	}
	expected_events := []TestEvent{{e: config_load}}
	expected_events = append(expected_events,
		watchpointSet(nil, ct.SyscallRecvBuf, readbufsz, syscall_entry_line, ct.DataFlow, &tainting_param, nil)...)

	// Second read
	readbufsz -= uint64(len(config_params))
	config_load.Size = readbufsz
	expected_events = append(expected_events, TestEvent{e: config_load})
	expected_events = append(expected_events,
		watchpointSet(nil, ct.SyscallRecvBuf, readbufsz, syscall_entry_line, ct.DataFlow, &tainting_param, nil)...)

	// bytes2
	val := string(config_params)
	sz := uint64(len(val))
	expected_events = append(expected_events, TestEvent{
		e:        ct.Event{EventType: ct.WatchpointSet, Size: sz, Expression: "bytes2", Line: 24},
		taint_sz: sz})

	testing_tainting_param := tainting_param
	testing_tainting_param.Param.Param = "testing"
	//testing := ct.MakeTaintingVals(&testing_tainting_param, nil)

	helper := func(paramName string, row, col int) *ct.TaintingVals {
		ret := tainting_param
		ret.Param.Param = paramName
		ret.Param.Row_number = row
		ret.Param.Column_number = col
		tv := ct.MakeTaintingVals(&ret, nil)
		return &tv
	}

	tvs := []*ct.TaintingVals{
		// `{"`
		helper("", 0, 0), helper("", 0, 0),
		// `apps`
		helper("apps", 0, 2), helper("apps", 0, 3), helper("apps", 0, 4), helper("apps", 0, 5),
		// `":{"`
		helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0),
		// `listen`
		helper("apps.listen", 0, 10), helper("apps.listen", 0, 11), helper("apps.listen", 0, 12), helper("apps.listen", 0, 13), helper("apps.listen", 0, 14), helper("apps.listen", 0, 15),
		// `":["`
		helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0),
		// `:2015`
		helper("apps.listen[0]", 0, 20), helper("apps.listen[0]", 0, 21), helper("apps.listen[0]", 0, 22), helper("apps.listen[0]", 0, 23), helper("apps.listen[0]", 0, 24),
		// `","`
		helper("", 0, 0), helper("", 0, 0), helper("", 0, 0),
		// `:2016`
		helper("apps.listen[1]", 0, 28), helper("apps.listen[1]", 0, 29), helper("apps.listen[1]", 0, 30), helper("apps.listen[1]", 0, 31), helper("apps.listen[1]", 0, 32),
		// `"]}}`
		helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0),
	}

	for _, tv := range tvs {
		expected_events = append(expected_events, TestEvent{
			e: ct.Event{EventType: ct.MemParamMapUpdate, Size: 1, TaintingVals: tv, Line: 24},
		})
	}

	// The usual syntax for passing args from dlv to target doesn't work in test
	os.Setenv("config", target_config_file)
	run(t, &config, expected_events, &TestConfig{checkDupEvents: true})
}

// TODO: Update test to work with row/col numbers
// func TestLoadConfigParamJSONFull(t *testing.T) {
// 	// Flattened original JSON
// 	config_params := []byte(`{"apps":{"http":{"servers":{"example":{"listen":[":2015"],"routes":[{"handle":[{"handler":"static_response","body":"Hello, world!"}]}]}}}}}`)

// 	target_config_file := filepath.Join(t.TempDir(), "target_config.json")
// 	assertNoError(os.WriteFile(target_config_file, config_params, 0666), t, "WriteFile")

// 	dlv_config_path := t.TempDir()
// 	assertNoError(os.MkdirAll(dlv_config_path+"/dlv", 0770), t, "Mkdir")
// 	dlv_config_file := filepath.Join(dlv_config_path, "dlv", "config.yml")
// 	dlv_config := fmt.Sprintf("target-config-files: [%v]", target_config_file)
// 	assertNoError(os.WriteFile(dlv_config_file, []byte(dlv_config), 0666), t, "WriteFile")
// 	os.Setenv("XDG_CONFIG_HOME", dlv_config_path)

// 	config := Config("load_config_param_JSON_full.go", "", 0)
// 	config.Config_file_type = 1 // JSON

// 	tainting_param := ct.TaintingParam{
// 		Param: ct.Param{
// 			Module: config.Module,
// 			File:   target_config_file,
// 		},
// 		Flow: ct.DataFlow,
// 	}
// 	tainting_vals := ct.MakeTaintingVals(&tainting_param, nil)

// 	// First read
// 	readbufsz := uint64(512)
// 	config_load := ct.Event{
// 		EventType:    ct.ConfigLoad,
// 		Size:         readbufsz,
// 		TaintingVals: &tainting_vals,
// 		Line:         syscall_entry_line,
// 	}
// 	expected_events := []TestEvent{{e: config_load}}
// 	expected_events = append(expected_events,
// 		watchpointSet(nil, ct.SyscallRecvBuf, readbufsz, syscall_entry_line, ct.DataFlow, &tainting_param, nil)...)

// 	// Second read (EOF)
// 	readbufsz -= uint64(len(config_params))
// 	config_load.Size = readbufsz
// 	expected_events = append(expected_events, TestEvent{e: config_load})
// 	expected_events = append(expected_events,
// 		watchpointSet(nil, ct.SyscallRecvBuf, readbufsz, syscall_entry_line, ct.DataFlow, &tainting_param, nil)...)

// 	// bytes2 watchpoint
// 	val := string(config_params)
// 	sz := uint64(len(val))
// 	expected_events = append(expected_events, TestEvent{
// 		e:        ct.Event{EventType: ct.WatchpointSet, Size: sz, Expression: "bytes2", Line: 24},
// 		taint_sz: sz,
// 	})

// 	empty := tainting_param
// 	empty.Param.Param = ""
// 	empty_tv := ct.MakeTaintingVals(&empty, nil)

// 	apps := tainting_param
// 	apps.Param.Param = "apps"
// 	apps_tv := ct.MakeTaintingVals(&apps, nil)

// 	http := tainting_param
// 	http.Param.Param = "apps.http"
// 	http_tv := ct.MakeTaintingVals(&http, nil)

// 	servers := tainting_param
// 	servers.Param.Param = "apps.http.servers"
// 	servers_tv := ct.MakeTaintingVals(&servers, nil)

// 	example := tainting_param
// 	example.Param.Param = "apps.http.servers.example"
// 	example_tv := ct.MakeTaintingVals(&example, nil)

// 	listen := tainting_param
// 	listen.Param.Param = "apps.http.servers.example.listen"
// 	listen_tv := ct.MakeTaintingVals(&listen, nil)

// 	listen0 := tainting_param
// 	listen0.Param.Param = "apps.http.servers.example.listen[0]"
// 	listen0_tv := ct.MakeTaintingVals(&listen0, nil)

// 	routes := tainting_param
// 	routes.Param.Param = "apps.http.servers.example.routes"
// 	routes_tv := ct.MakeTaintingVals(&routes, nil)

// 	handle := tainting_param
// 	handle.Param.Param = "apps.http.servers.example.routes[0].handle"
// 	handle_tv := ct.MakeTaintingVals(&handle, nil)

// 	handler := tainting_param
// 	handler.Param.Param = "apps.http.servers.example.routes[0].handle[0].handler"
// 	handler_tv := ct.MakeTaintingVals(&handler, nil)

// 	body := tainting_param
// 	body.Param.Param = "apps.http.servers.example.routes[0].handle[0].body"
// 	body_tv := ct.MakeTaintingVals(&body, nil)

// 	tvs := []*ct.TaintingVals{
// 		// {"apps":{"http":{"servers":{"example":{"listen":[":2015"],"routes":[{"handle":[{"handler":"static_response","body":"Hello, world!"}]}]}}}}}
// 		&empty_tv,   // {
// 		&empty_tv,   // "
// 		&apps_tv,    // a
// 		&apps_tv,    // p
// 		&apps_tv,    // p
// 		&apps_tv,    // s
// 		&empty_tv,   // "
// 		&empty_tv,   // :
// 		&empty_tv,   // {
// 		&empty_tv,   // "
// 		&http_tv,    // h
// 		&http_tv,    // t
// 		&http_tv,    // t
// 		&http_tv,    // p
// 		&empty_tv,   // "
// 		&empty_tv,   // :
// 		&empty_tv,   // {
// 		&empty_tv,   // "
// 		&servers_tv, // s
// 		&servers_tv, // e
// 		&servers_tv, // r
// 		&servers_tv, // v
// 		&servers_tv, // e
// 		&servers_tv, // r
// 		&servers_tv, // s
// 		&empty_tv,   // "
// 		&empty_tv,   // :
// 		&empty_tv,   // {
// 		&empty_tv,   // "
// 		&example_tv, // e
// 		&example_tv, // x
// 		&example_tv, // a
// 		&example_tv, // m
// 		&example_tv, // p
// 		&example_tv, // l
// 		&example_tv, // e
// 		&empty_tv,   // "
// 		&empty_tv,   // :
// 		&empty_tv,   // {
// 		&empty_tv,   // "
// 		&listen_tv,  // l
// 		&listen_tv,  // i
// 		&listen_tv,  // s
// 		&listen_tv,  // t
// 		&listen_tv,  // e
// 		&listen_tv,  // n
// 		&empty_tv,   // "
// 		&empty_tv,   // :
// 		&empty_tv,   // [
// 		&empty_tv,   // "
// 		// :2015
// 		&listen0_tv, // :
// 		&listen0_tv, // 2
// 		&listen0_tv, // 0
// 		&listen0_tv, // 1
// 		&listen0_tv, // 5
// 		&empty_tv,   // "
// 		&empty_tv,   // ]
// 		&empty_tv,   // ,
// 		&empty_tv,   // "
// 		&routes_tv,  // r
// 		&routes_tv,  // o
// 		&routes_tv,  // u
// 		&routes_tv,  // t
// 		&routes_tv,  // e
// 		&routes_tv,  // s
// 		&empty_tv,   // "
// 		&empty_tv,   // :
// 		&empty_tv,   // [
// 		&empty_tv,   // {
// 		&empty_tv,   // "
// 		&handle_tv,  // h
// 		&handle_tv,  // a
// 		&handle_tv,  // n
// 		&handle_tv,  // d
// 		&handle_tv,  // l
// 		&handle_tv,  // e
// 		&empty_tv,   // "
// 		&empty_tv,   // :
// 		&empty_tv,   // [
// 		&empty_tv,   // {
// 		&empty_tv,   // "
// 		&handler_tv, // h
// 		&handler_tv, // a
// 		&handler_tv, // n
// 		&handler_tv, // d
// 		&handler_tv, // l
// 		&handler_tv, // e
// 		&handler_tv, // r
// 		&empty_tv,   // "
// 		&empty_tv,   // :
// 		&empty_tv,   // "
// 		// static response
// 		&handler_tv, // s
// 		&handler_tv, // t
// 		&handler_tv, // a
// 		&handler_tv, // t
// 		&handler_tv, // i
// 		&handler_tv, // c
// 		&handler_tv, // _
// 		&handler_tv, // r
// 		&handler_tv, // e
// 		&handler_tv, // s
// 		&handler_tv, // p
// 		&handler_tv, // o
// 		&handler_tv, // n
// 		&handler_tv, // s
// 		&handler_tv, // e
// 		&empty_tv,   // "
// 		&empty_tv,   // ,
// 		&empty_tv,   // "
// 		&body_tv,    // b
// 		&body_tv,    // o
// 		&body_tv,    // d
// 		&body_tv,    // y
// 		&empty_tv,   // "
// 		&empty_tv,   // :
// 		&empty_tv,   // "
// 		// Hello, world!
// 		&body_tv,  // H
// 		&body_tv,  // e
// 		&body_tv,  // l
// 		&body_tv,  // l
// 		&body_tv,  // o
// 		&body_tv,  // ,
// 		&body_tv,  //
// 		&body_tv,  // w
// 		&body_tv,  // o
// 		&body_tv,  // r
// 		&body_tv,  // l
// 		&body_tv,  // d
// 		&body_tv,  // !
// 		&empty_tv, // "
// 		&empty_tv, // }
// 		&empty_tv, // ]
// 		&empty_tv, // }
// 		&empty_tv, // ]
// 		&empty_tv, // }
// 		&empty_tv, // }
// 		&empty_tv, // }
// 		&empty_tv, // }
// 		&empty_tv, // }
// 	}

// 	for _, tv := range tvs {
// 		expected_events = append(expected_events, TestEvent{
// 			e: ct.Event{EventType: ct.MemParamMapUpdate, Size: 1, TaintingVals: tv, Line: 24},
// 		})
// 	}

// 	os.Setenv("config", target_config_file)
// 	run(t, &config, expected_events, &TestConfig{checkDupEvents: true})
// }

// Also tests copy builtin
func TestLoadConfigParamYAML(t *testing.T) {
	// Write a config file, tell dlv where it is
	config_params := []byte(`param1: 1`)
	target_config_file := filepath.Join(t.TempDir(), "target_config.YAML")
	assertNoError(os.WriteFile(target_config_file, config_params, 0666), t, "WriteFile")
	dlv_config_path := t.TempDir()
	assertNoError(os.MkdirAll(dlv_config_path+"/dlv", 0770), t, "Mkdir")
	dlv_config_file := filepath.Join(dlv_config_path, "dlv", "config.yml")
	dlv_config := fmt.Sprintf("target-config-files: [%v]", target_config_file)
	assertNoError(os.WriteFile(dlv_config_file, []byte(dlv_config), 0666), t, "WriteFile")
	os.Setenv("XDG_CONFIG_HOME", dlv_config_path)

	config := Config("load_config_param_YAML.go", "", 0)
	config.Config_file_type = 2
	//config.LoggerLevel = "Debug"

	tainting_param := ct.TaintingParam{
		Param: ct.Param{
			Module: config.Module,
			File:   target_config_file,
		},
		Flow: ct.DataFlow,
	}

	tainting_vals := ct.MakeTaintingVals(&tainting_param, nil)

	// Two read syscalls: one reads whole file, second advances buf pointer and reads nothing (EOF)
	// First read
	readbufsz := uint64(512) // ReadFile uses buf of this size (0x200) for smaller files
	config_load := ct.Event{
		EventType:    ct.ConfigLoad,
		Size:         readbufsz,
		TaintingVals: &tainting_vals,
		Line:         syscall_entry_line,
	}
	expected_events := []TestEvent{{e: config_load}}
	expected_events = append(expected_events,
		watchpointSet(nil, ct.SyscallRecvBuf, readbufsz, syscall_entry_line, ct.DataFlow, &tainting_param, nil)...)

	// Second read
	readbufsz -= uint64(len(config_params))
	config_load.Size = readbufsz
	expected_events = append(expected_events, TestEvent{e: config_load})
	expected_events = append(expected_events,
		watchpointSet(nil, ct.SyscallRecvBuf, readbufsz, syscall_entry_line, ct.DataFlow, &tainting_param, nil)...)

	// bytes2
	val := `param1: 1`

	sz := uint64(len(val))
	expected_events = append(expected_events, TestEvent{
		e:        ct.Event{EventType: ct.WatchpointSet, Size: sz, Expression: "bytes2", Line: 24},
		taint_sz: sz})

	empty_tainting_param := tainting_param
	empty_tainting_param.Param.Param = ""
	empty_tainting_vals := ct.MakeTaintingVals(&empty_tainting_param, nil)

	param_tainting_param := tainting_param
	param_tainting_param.Param.Param = "param1"

	// chars: param1
	for offset := 0; offset <= 5; offset++ {
		param_tainting_param.Param.Column_number = offset
		param_tainting_param.Param.Row_number = 0

		param_tainting_vals := ct.MakeTaintingVals(&param_tainting_param, nil)
		expected_events = append(expected_events, TestEvent{
			e: ct.Event{EventType: ct.MemParamMapUpdate, Size: 1, TaintingVals: &param_tainting_vals, Line: 24},
		})
	}
	// chars: :
	for i := 6; i <= 7; i++ {
		expected_events = append(expected_events, TestEvent{
			e: ct.Event{EventType: ct.MemParamMapUpdate, Size: 1, TaintingVals: &empty_tainting_vals, Line: 24},
		})
	}
	param_tainting_param.Param.Column_number = 8
	param_tainting_param.Param.Row_number = 0

	param_tainting_vals := ct.MakeTaintingVals(&param_tainting_param, nil)
	expected_events = append(expected_events, TestEvent{
		e: ct.Event{EventType: ct.MemParamMapUpdate, Size: 1, TaintingVals: &param_tainting_vals, Line: 24},
	})

	// The usual syntax for passing args from dlv to target doesn't work in test
	os.Setenv("config", target_config_file)
	run(t, &config, expected_events, &TestConfig{checkDupEvents: true})
}

func TestLoadConfigParamYAMLComplex(t *testing.T) {
	// Write a config file, tell dlv where it is
	config_params := []byte(
		"global:\n" +
			"  scrape_interval: 30s\n" +
			"rule_files:\n" +
			"  - /etc/a.yaml\n" +
			"scrape_configs:\n" +
			"  - job_name: svc/0\n" +
			"    kubernetes_sd_configs:\n" +
			"      - role: endpoints\n" +
			"        namespaces:\n" +
			"          names:\n" +
			"            - kube_system\n",
	)
	target_config_file := filepath.Join(t.TempDir(), "target_config.YAML")
	assertNoError(os.WriteFile(target_config_file, config_params, 0666), t, "WriteFile")
	dlv_config_path := t.TempDir()
	assertNoError(os.MkdirAll(dlv_config_path+"/dlv", 0770), t, "Mkdir")
	dlv_config_file := filepath.Join(dlv_config_path, "dlv", "config.yml")
	dlv_config := fmt.Sprintf("target-config-files: [%v]", target_config_file)
	assertNoError(os.WriteFile(dlv_config_file, []byte(dlv_config), 0666), t, "WriteFile")
	os.Setenv("XDG_CONFIG_HOME", dlv_config_path)

	config := Config("load_config_param_complex_YAML.go", "", 0)
	config.Config_file_type = 2
	//config.LoggerLevel = "Debug"

	tainting_param := ct.TaintingParam{
		Param: ct.Param{
			Module: config.Module,
			File:   target_config_file,
		},
		Flow: ct.DataFlow,
	}

	tainting_vals := ct.MakeTaintingVals(&tainting_param, nil)

	// Two read syscalls: one reads whole file, second advances buf pointer and reads nothing (EOF)
	// First read
	readbufsz := uint64(512) // ReadFile uses buf of this size (0x200) for smaller files
	config_load := ct.Event{
		EventType:    ct.ConfigLoad,
		Size:         readbufsz,
		TaintingVals: &tainting_vals,
		Line:         syscall_entry_line,
	}
	expected_events := []TestEvent{{e: config_load}}
	expected_events = append(expected_events,
		watchpointSet(nil, ct.SyscallRecvBuf, readbufsz, syscall_entry_line, ct.DataFlow, &tainting_param, nil)...)

	// Second read
	readbufsz -= uint64(len(config_params))
	config_load.Size = readbufsz
	expected_events = append(expected_events, TestEvent{e: config_load})
	expected_events = append(expected_events,
		watchpointSet(nil, ct.SyscallRecvBuf, readbufsz, syscall_entry_line, ct.DataFlow, &tainting_param, nil)...)

	// bytes2
	val := string(config_params)
	sz := uint64(len(val))
	expected_events = append(expected_events, TestEvent{
		e:        ct.Event{EventType: ct.WatchpointSet, Size: sz, Expression: "bytes2", Line: 36},
		taint_sz: sz})

	testing_tainting_param := tainting_param
	testing_tainting_param.Param.Param = "testing"
	//testing := ct.MakeTaintingVals(&testing_tainting_param, nil)

	helper := func(paramName string, row, col int) *ct.TaintingVals {
		ret := tainting_param
		ret.Param.Param = paramName
		ret.Param.Row_number = row
		ret.Param.Column_number = col
		tv := ct.MakeTaintingVals(&ret, nil)
		return &tv
	}

	tvs := []*ct.TaintingVals{
		// `global:\n `
		helper("global", 0, 0), helper("global", 0, 1), helper("global", 0, 2), helper("global", 0, 3), helper("global", 0, 4), helper("global", 0, 5), helper("", 0, 0), helper("", 0, 0),
		// `  scrape_interval: 30s\n`
		helper("", 0, 0), helper("", 0, 0), helper("global.scrape_interval", 1, 2), helper("global.scrape_interval", 1, 3), helper("global.scrape_interval", 1, 4), helper("global.scrape_interval", 1, 5), helper("global.scrape_interval", 1, 6), helper("global.scrape_interval", 1, 7), helper("global.scrape_interval", 1, 8), helper("global.scrape_interval", 1, 9), helper("global.scrape_interval", 1, 10), helper("global.scrape_interval", 1, 11), helper("global.scrape_interval", 1, 12), helper("global.scrape_interval", 1, 13), helper("global.scrape_interval", 1, 14), helper("global.scrape_interval", 1, 15), helper("global.scrape_interval", 1, 16), helper("", 0, 0), helper("", 0, 0), helper("global.scrape_interval", 1, 19), helper("global.scrape_interval", 1, 20), helper("global.scrape_interval", 1, 21), helper("", 0, 0),
		// `"rule_files:\n"`
		helper("rule_files", 2, 0), helper("rule_files", 2, 1), helper("rule_files", 2, 2), helper("rule_files", 2, 3), helper("rule_files", 2, 4), helper("rule_files", 2, 5), helper("rule_files", 2, 6), helper("rule_files", 2, 7), helper("rule_files", 2, 8), helper("rule_files", 2, 9), helper("", 0, 0), helper("", 0, 0),
		// `  - /etc/a.yaml\n`
		helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("rule_files[0]", 3, 4), helper("rule_files[0]", 3, 5), helper("rule_files[0]", 3, 6), helper("rule_files[0]", 3, 7), helper("rule_files[0]", 3, 8), helper("rule_files[0]", 3, 9), helper("rule_files[0]", 3, 10), helper("rule_files[0]", 3, 11), helper("rule_files[0]", 3, 12), helper("rule_files[0]", 3, 13), helper("rule_files[0]", 3, 14), helper("", 0, 0),
		// `scrape_configs:\n`
		helper("scrape_configs", 4, 0), helper("scrape_configs", 4, 1), helper("scrape_configs", 4, 2), helper("scrape_configs", 4, 3), helper("scrape_configs", 4, 4), helper("scrape_configs", 4, 5), helper("scrape_configs", 4, 6), helper("scrape_configs", 4, 7), helper("scrape_configs", 4, 8), helper("scrape_configs", 4, 9), helper("scrape_configs", 4, 10), helper("scrape_configs", 4, 11), helper("scrape_configs", 4, 12), helper("scrape_configs", 4, 13), helper("", 0, 0), helper("", 0, 0),
		// `  - job_name: svc/0\n`
		helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("scrape_configs[0].job_name", 5, 4), helper("scrape_configs[0].job_name", 5, 5), helper("scrape_configs[0].job_name", 5, 6), helper("scrape_configs[0].job_name", 5, 7), helper("scrape_configs[0].job_name", 5, 8), helper("scrape_configs[0].job_name", 5, 9), helper("scrape_configs[0].job_name", 5, 10), helper("scrape_configs[0].job_name", 5, 11), helper("", 0, 0), helper("", 0, 0), helper("scrape_configs[0].job_name", 5, 14), helper("scrape_configs[0].job_name", 5, 15), helper("scrape_configs[0].job_name", 5, 16), helper("scrape_configs[0].job_name", 5, 17), helper("scrape_configs[0].job_name", 5, 18), helper("", 0, 0),
		// `    kubernetes_sd_configs:\n`
		helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("scrape_configs[0].kubernetes_sd_configs", 6, 4), helper("scrape_configs[0].kubernetes_sd_configs", 6, 5), helper("scrape_configs[0].kubernetes_sd_configs", 6, 6), helper("scrape_configs[0].kubernetes_sd_configs", 6, 7), helper("scrape_configs[0].kubernetes_sd_configs", 6, 8), helper("scrape_configs[0].kubernetes_sd_configs", 6, 9), helper("scrape_configs[0].kubernetes_sd_configs", 6, 10), helper("scrape_configs[0].kubernetes_sd_configs", 6, 11), helper("scrape_configs[0].kubernetes_sd_configs", 6, 12), helper("scrape_configs[0].kubernetes_sd_configs", 6, 13), helper("scrape_configs[0].kubernetes_sd_configs", 6, 14), helper("scrape_configs[0].kubernetes_sd_configs", 6, 15), helper("scrape_configs[0].kubernetes_sd_configs", 6, 16), helper("scrape_configs[0].kubernetes_sd_configs", 6, 17), helper("scrape_configs[0].kubernetes_sd_configs", 6, 18), helper("scrape_configs[0].kubernetes_sd_configs", 6, 19), helper("scrape_configs[0].kubernetes_sd_configs", 6, 20), helper("scrape_configs[0].kubernetes_sd_configs", 6, 21), helper("scrape_configs[0].kubernetes_sd_configs", 6, 22), helper("scrape_configs[0].kubernetes_sd_configs", 6, 23), helper("scrape_configs[0].kubernetes_sd_configs", 6, 24), helper("", 0, 0), helper("", 0, 0),
		// `      - role: endpoints\n`
		helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("scrape_configs[0].kubernetes_sd_configs[0].role", 7, 8), helper("scrape_configs[0].kubernetes_sd_configs[0].role", 7, 9), helper("scrape_configs[0].kubernetes_sd_configs[0].role", 7, 10), helper("scrape_configs[0].kubernetes_sd_configs[0].role", 7, 11), helper("", 0, 0), helper("", 0, 0), helper("scrape_configs[0].kubernetes_sd_configs[0].role", 7, 14), helper("scrape_configs[0].kubernetes_sd_configs[0].role", 7, 15), helper("scrape_configs[0].kubernetes_sd_configs[0].role", 7, 16), helper("scrape_configs[0].kubernetes_sd_configs[0].role", 7, 17), helper("scrape_configs[0].kubernetes_sd_configs[0].role", 7, 18), helper("scrape_configs[0].kubernetes_sd_configs[0].role", 7, 19), helper("scrape_configs[0].kubernetes_sd_configs[0].role", 7, 20), helper("scrape_configs[0].kubernetes_sd_configs[0].role", 7, 21), helper("scrape_configs[0].kubernetes_sd_configs[0].role", 7, 22), helper("", 0, 0),
		// `        namespaces:\n`
		helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces", 8, 8), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces", 8, 9), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces", 8, 10), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces", 8, 11), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces", 8, 12), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces", 8, 13), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces", 8, 14), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces", 8, 15), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces", 8, 16), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces", 8, 17), helper("", 0, 0), helper("", 0, 0),
		// `          names:\n`
		helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces.names", 9, 10), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces.names", 9, 11), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces.names", 9, 12), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces.names", 9, 13), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces.names", 9, 14), helper("", 0, 0), helper("", 0, 0),
		// `            - kube_system\n`
		helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("", 0, 0), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces.names[0]", 10, 14), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces.names[0]", 10, 15), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces.names[0]", 10, 16), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces.names[0]", 10, 17), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces.names[0]", 10, 18), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces.names[0]", 10, 19), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces.names[0]", 10, 20), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces.names[0]", 10, 21), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces.names[0]", 10, 22), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces.names[0]", 10, 23), helper("scrape_configs[0].kubernetes_sd_configs[0].namespaces.names[0]", 10, 24), helper("", 0, 0),
	}

	for _, tv := range tvs {
		expected_events = append(expected_events, TestEvent{
			e: ct.Event{EventType: ct.MemParamMapUpdate, Size: 1, TaintingVals: tv, Line: 36},
		})
	}

	// The usual syntax for passing args from dlv to target doesn't work in test
	os.Setenv("config", target_config_file)
	run(t, &config, expected_events, &TestConfig{checkDupEvents: true})
}

func TestCaddyManualScan(t *testing.T) {
	client_endpoint := "127.0.0.1:46402"
	server_endpoint := "127.0.0.1:2015"
	core_module := "caddy_core"
	http_module := "http"
	caddy_client_module := "caddy_client"
	core_behavior_map := make(ct.BehaviorMap)
	static_resp_behavior_map := make(ct.BehaviorMap)

	tainting_param := ct.TaintingParam{
		Param: ct.Param{
			Module: core_module,
			File:   ct.ConfigAPI,
			Param:  "apps.http.servers.routes.handle.static_response.body",
		},
		Flow: ct.DataFlow,
	}

	tainting_vals := ct.MakeTaintingVals(&tainting_param, nil)

	// 1. PARAM => HTTP PROVISION ARGS
	provision_arg := ct.BehaviorValue{
		Behavior_type: ct.FnArg,
		Function_arg: ct.FunctionArg{
			Function_name: "caddyhttp.(*App).Provision()",
		},
		Send_module: core_module,
		Recv_module: http_module,
	}

	// XXX ignore all offsets for now
	// http.Provision.App, http.Provision.Ctx_AppsRaw, http.Provision.Ctx_Ancestry
	http_args := []string{"app.Servers[hello].Routes[0].HandlersRaw[0]",
		"ctx.cfg.AppsRaw[http]",
		"ctx.ancestry[0].Servers[hello].Routes[0].HandlersRaw[0]"}
	// TODO dot doesn't seem to like quotes in map key (looks ok in .gv, but .svg is weird)
	nonraw_http_args := []ct.BehaviorValue{}

	for i := 0; i < len(http_args); i++ {
		provision_arg.Function_arg.Arg_name = http_args[i]
		core_behavior_map[provision_arg] = tainting_vals
		if !strings.Contains(http_args[i], "AppsRaw") {
			nonraw_http_args = append(nonraw_http_args, provision_arg)
		}
	}

	// 2. PARAM => NON-HTTP PROVISION ARGS
	static_resp_module := "http.handlers.static_response"

	// module ID => module_pkg.provision_recvr
	other_args := map[string]string{
		"tls":               "caddytls.(*TLS)",
		"events":            "caddyevents.(*App)",
		"tls.issuance.acme": "caddytls.(*ACMEIssuer)",
		"admin.api.metrics": "metrics.(*AdminMetrics)",
		"admin.api.pki":     "caddypki.(*adminAPI)",
	}

	for module_ID, provision_prefix := range other_args {
		provision_arg.Function_arg.Function_name = provision_prefix + "." + "Provision()"
		provision_arg.Function_arg.Arg_name = "ctx.<X>"
		provision_arg.Recv_module = module_ID
		core_behavior_map[provision_arg] = tainting_vals
	}

	static_resp_servehttp_args := []string{"s.Body", "w.<X>"}
	servehttp_arg := provision_arg
	servehttp_arg.Function_arg.Function_name = "caddyhttp.StaticResponse.ServeHTTP()"
	servehttp_arg.Send_module = http_module
	servehttp_arg.Recv_module = static_resp_module
	tainting_http_args := []ct.TaintingBehavior{
		{Behavior: nonraw_http_args[0], Flow: ct.DataFlow},
		{Behavior: nonraw_http_args[1], Flow: ct.DataFlow},
	}

	http_behavior_map := make(ct.BehaviorMap)
	http_tainting_vals := ct.MakeTaintingVals(nil, &tainting_http_args[0])
	http_tainting_vals.Behaviors.Insert(tainting_http_args[1])
	servehttp_tainting_vals := ct.TaintingVals{}

	for i, static_arg := range static_resp_servehttp_args {
		servehttp_arg.Function_arg.Arg_name = static_arg
		// 2. NON-RAW HTTP PROVISION ARGS => STATIC_RESP SERVEHTTP ARGS
		http_behavior_map[servehttp_arg] = http_tainting_vals
		tainting_servehttp_arg := ct.TaintingBehavior{Behavior: servehttp_arg, Flow: ct.DataFlow}
		if i == 0 {
			servehttp_tainting_vals = ct.MakeTaintingVals(nil, &tainting_servehttp_arg)
		} else {
			servehttp_tainting_vals.Behaviors.Insert(tainting_servehttp_arg)
		}
	}

	// 3. STATIC_RESP SERVEHTTP ARGS => HTTP RESPONSE
	sent_msg := ct.BehaviorValue{
		Behavior_type: ct.NetworkMsg,
		Network_msg: ct.NetworkMessage{
			Send_endpoint: server_endpoint,
			Recv_endpoint: client_endpoint,
			Transport:     "tcp",
		},
		Send_module: static_resp_module,
		Recv_module: caddy_client_module,
	}

	static_resp_behavior_map[sent_msg] = servehttp_tainting_vals

	// 4. WRITE GRAPH
	behavior_maps := []ct.BehaviorMap{core_behavior_map, http_behavior_map, static_resp_behavior_map}
	behavior_map_files := []string{}

	for i, module := range []string{core_module, http_module, static_resp_module} {
		file := outputFile(t, module+"_behavior_map.csv")
		assertNoError(ct.WriteBehaviorMap(file, behavior_maps[i]), t, "write")
		behavior_map_files = append(behavior_map_files, file)
	}
	_, err := ct.WriteGraph("caddy_graph.gv", behavior_map_files)
	assertNoError(err, t, "write graph")
}

func TestNetworkMessages(t *testing.T) {
	// SENDER
	initial_line := 34
	client_config := Config("behavior_client.go", "config[1]", initial_line)
	client_config.Module = "send_module"
	client_config.Event_log_filename = client_config.Module + "_event_log.csv"
	client_config.Behavior_map_filename = client_config.Module + "_behavior_map.csv"

	client_endpoint := "127.0.0.1:5050"
	server_endpoint := "127.0.0.1:6060"
	sent_msg := ct.BehaviorValue{
		Offset:        1,
		Behavior_type: ct.NetworkMsg,
		Network_msg: ct.NetworkMessage{
			Send_endpoint: client_endpoint,
			Recv_endpoint: server_endpoint,
			Transport:     "tcp",
		},
		Send_module: client_config.Module,
	}
	expected_events :=
		watchpointSet(&client_config, client_config.Initial_watchexpr, uint64(1), initial_line, ct.DataFlow, nil, nil)

	expected_events = append(expected_events, messageSend(&client_config, sent_msg, 6, 1, nil)...)
	go run(t, &client_config, expected_events, &TestConfig{checkDupEvents: true})

	// RECEIVER
	server_config := Config("behavior_server.go", "", 0)
	server_config.Module = "recv_module"
	server_config.Event_log_filename = server_config.Module + "_event_log.csv"
	server_config.Behavior_map_filename = server_config.Module + "_behavior_map.csv"
	server_config.Server_endpoint = "localhost:4041"

	recvd_msg := ct.BehaviorValue{
		Behavior_type: ct.NetworkMsg,
		Network_msg: ct.NetworkMessage{
			Send_endpoint: client_endpoint,
			Recv_endpoint: server_endpoint,
			Transport:     "tcp",
		},
		Recv_module: server_config.Module,
	}
	tainting_behavior := ct.TaintingBehavior{
		Behavior: recvd_msg,
		Flow:     ct.DataFlow,
	}
	expected_events = messageRecv(tainting_behavior, 7)

	expected_events = append(expected_events,
		watchpointSet(nil, "msg_B[1]", uint64(1), 38, ct.DataFlow, nil, &tainting_behavior)...)
	tainting_behavior.Behavior.Offset = 1 // msg_B[2] tainted by msg_A[1]
	expected_events = append(expected_events,
		watchpointSet(nil, "msg_B[2]", uint64(1), 39, ct.DataFlow, nil, &tainting_behavior)...)

	// Write() accesses msg_B[0] => server assumes 16B access thus returns to client bc of wps on msg_B[1] and msg_B[2]
	// Client then sees Write accesses msg_B[:] => propagates into Write(), i.e. sets wp on its arg (b, which is alias of msg_B)
	// and redundantly updates m-c for the tainted portion i.e. msg_B[1] and msg_B[2]
	write_line := 192 // net.go
	mc_msg_B_1 := expected_events[len(expected_events)-3]
	mc_msg_B_1.e.Line = write_line
	mc_msg_B_2 := expected_events[len(expected_events)-1]
	mc_msg_B_2.e.Line = write_line
	expected_events = append(expected_events,
		TestEvent{
			e:            ct.Event{EventType: ct.WatchpointSet, Size: 3, Expression: "b", Line: write_line},
			taint_sz:     2,
			taint_offset: 1,
		},
		mc_msg_B_1, mc_msg_B_2,
	)

	sent_msg = ct.BehaviorValue{
		Offset:        1,
		Behavior_type: ct.NetworkMsg,
		Network_msg: ct.NetworkMessage{
			Send_endpoint: server_endpoint,
			Recv_endpoint: client_endpoint,
			Transport:     "tcp",
		},
		Send_module: server_config.Module,
	}
	tainting_behavior.Behavior.Offset = 0 // msg_B[1] tainted by msg_A[0] (messageSend takes care of rest of msg_B)
	expected_events = append(expected_events, messageSend(nil, sent_msg, 3, 2, &tainting_behavior)...)

	run(t, &server_config, expected_events, &TestConfig{checkDupEvents: true})

	expected_lines := []string{
		"strict digraph {",
		"\"{ {send_module  config[1]} {0    {  } { }}}\" [  weight=0 ];",
		"\"{ {send_module  config[1]} {0    {  } { }}}\" -> \"{ {  } {1   network message {127.0.0.1:5050 127.0.0.1:6060 tcp} { }}}\" [ EdgeType=\"Data Flow\",  weight=0 ];",
		"\"{ {  } {1   network message {127.0.0.1:5050 127.0.0.1:6060 tcp} { }}}\" [  weight=0 ];",
		"\"{ {  } {1   network message {127.0.0.1:5050 127.0.0.1:6060 tcp} { }}}\" -> \"{ {  } {2   network message {127.0.0.1:6060 127.0.0.1:5050 tcp} { }}}\" [ EdgeType=\"Data Flow\",  weight=0 ];",
		"\"{ {  } {2   network message {127.0.0.1:6060 127.0.0.1:5050 tcp} { }}}\" [  weight=0 ];",
		"}",
	}

	// Get behavior map filenames after run() modifies them
	behavior_maps := []string{client_config.Behavior_map_filename, server_config.Behavior_map_filename}
	checkGraph(t, behavior_maps, "behavior_graph.gv", expected_lines)
}

func TestStructs(t *testing.T) {
	initial_line := 26
	config := Config("structs.go", "arr", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(16), initial_line, ct.DataFlow, nil, nil)

	expected_events = append(expected_events,
		watchpointSet(&config, "struct_lit.Data", uint64(16), 27, ct.DataFlow, nil, nil)...)
	// Set watchpoint on untainted struct field (since entire struct appears on line), but don't insert it to m-c
	expected_events = append(expected_events, TestEvent{
		e:        ct.Event{EventType: ct.WatchpointSet, Size: uint64(8), Expression: "struct_lit.fake", Line: 27},
		taint_sz: 0,
	})

	expected_events = append(expected_events,
		watchpointSet(&config, "s.Data", uint64(16), 29, ct.DataFlow, nil, nil)...)
	expected_events = append(expected_events, TestEvent{
		e:        ct.Event{EventType: ct.WatchpointSet, Size: uint64(8), Expression: "s.fake", Line: 29},
		taint_sz: 0,
	})

	expected_events = append(expected_events,
		watchpointSet(&config, "s_callee.Data", uint64(16), 20, ct.DataFlow, nil, nil)...)
	expected_events = append(expected_events, TestEvent{
		e:        ct.Event{EventType: ct.WatchpointSet, Size: uint64(8), Expression: "s_callee.fake", Line: 20},
		taint_sz: 0,
	})

	expected_events = append(expected_events,
		watchpointSet(&config, "s_caller.Data", uint64(16), 31, ct.DataFlow, nil, nil)...)
	expected_events = append(expected_events, TestEvent{
		e:        ct.Event{EventType: ct.WatchpointSet, Size: uint64(8), Expression: "s_caller.fake", Line: 31},
		taint_sz: 0,
	})

	expected_events = append(expected_events,
		watchpointSet(&config, "multiline_lit.Data", uint64(16), 33, ct.DataFlow, nil, nil)...)
	expected_events = append(expected_events, TestEvent{
		e:        ct.Event{EventType: ct.WatchpointSet, Size: uint64(8), Expression: "multiline_lit.fake", Line: 33},
		taint_sz: 0,
	})

	expected_events = append(expected_events,
		watchpointSet(&config, "nested.name.Data", uint64(16), 39, ct.DataFlow, nil, nil)...)
	expected_events = append(expected_events, TestEvent{
		e:        ct.Event{EventType: ct.WatchpointSet, Size: uint64(8), Expression: "nested.name.fake", Line: 39},
		taint_sz: 0,
	})

	expected_events = append(expected_events,
		watchpointSet(&config, "nested2.name.Data", uint64(16), 44, ct.DataFlow, nil, nil)...)
	expected_events = append(expected_events, TestEvent{
		e:        ct.Event{EventType: ct.WatchpointSet, Size: uint64(8), Expression: "nested2.name.fake", Line: 44},
		taint_sz: 0,
	})

	run(t, &config, expected_events, nil)
}

func TestAllocatorHTTP(t *testing.T) {
	initial_line := 27
	config := Config("allocator_http.go", "*ptr", initial_line)
	config.Move_wps = true
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(8), initial_line, ct.DataFlow, nil, nil)

	expected_events = append(expected_events,
		watchpointSet(&config, "x", uint64(8), 31, ct.DataFlow, nil, nil)...)

	run(t, &config, expected_events, nil)
}

func waitForServer(t *testing.T, stdout *saveOutput, stderr *saveOutput) {
	// Wait for server to start
	for ; len(stdout.savedOutput) == 0; time.Sleep(300 * time.Millisecond) {
	}
	if !strings.HasPrefix(string(stdout.savedOutput), "API server listening at:") {
		t.Fatalf("Delve server failed to start listening; stdout %v", string(stdout.savedOutput))
	}

	// Check for error
	if len(stderr.savedOutput) > 0 {
		t.Fatalf("Delve server errored while starting up")
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

// Build dlv server and client with version of go in PATH,
// and target with version in CT_TARGET_GO.
// Start server for a module, wait for client to exit/timeout.
// Note this may be called concurrently for multiple modules, so don't hardcode resources like filenames.
// TODO (minor) prefix log msgs with module to make clearer for tests that run multiple modules
// Note Fatalf shouldn't be called here - use Fail() instead (since it's called from goroutine)
func run(t *testing.T, config *ct.Config, expected_events []TestEvent, testcfg *TestConfig) {
	// Set up config
	config.Initial_bp_file = filepath.Join(protest.FindFixturesDir(), "conftamer", config.Initial_bp_file)
	if config.Initial_watchexpr != "" {
		config.Initial_bp_line = expected_events[0].e.Line
	}

	config_file := config.Module + "_client_config.yml"
	event_log := outputFile(t, config.Event_log_filename)
	behavior_map := outputFile(t, config.Behavior_map_filename)
	config.Event_log_filename = event_log
	config.Behavior_map_filename = behavior_map
	config_file = outputFile(t, config_file)

	ct.SaveConfig(config_file, *config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start dlv server
	var server_out saveOutput
	var server_err saveOutput

	client_bin := getClientBin(t)

	server := exec.CommandContext(ctx, getDlvBin(t), "debug", "--headless",
		"--api-version=2", "--accept-multiclient", "--listen", config.Server_endpoint, config.Initial_bp_file)
	t.Logf("Starting server: %v\n", strings.Join(server.Args, " "))
	server_out = saveOutput{}
	server_err = saveOutput{}
	server.Stdout = &server_out
	server.Stderr = &server_err

	// Set go version used to build target (after building server and client)
	if testcfg == nil || !testcfg.useLocalGo {
		path, target_go, err := protest.SetGoVersion()
		assertNoError(err, t, "set go version")
		defer func() {
			protest.UnSetGoVersion(path, target_go)
		}()
	}

	assertNoError(server.Start(), t, "start headless instance")
	waitForServer(t, &server_out, &server_err)

	// Run dlv client until exit
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	client := exec.CommandContext(ctx, client_bin, "-config="+config_file)
	t.Logf("Starting client: %v\n", strings.Join(client.Args, " "))

	var client_out saveOutput
	var client_err saveOutput
	client.Stdout = &client_out
	client.Stderr = &client_err

	if err := client.Run(); err != nil {
		if err.Error() == "signal: killed" {
			// Can occur with some tests, but not when run outside `go test`
			t.Logf("Test timeout or OOM - may cause failure if occurred before end")
		} else {
			t.Logf("Client exited with error: %v\n", err.Error())
			t.Fail()
		}
	}

	checkStderr(t, client_err.savedOutput, server_err.savedOutput)
	checkEvents(t, expected_events, config.Event_log_filename, testcfg)
}

// TODO check for warn/error/fatal log msgs
func checkStderr(t *testing.T, client_err []byte, server_err []byte) {
	// XXX fix this for logging in my fork of go
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

type TestEvent struct {
	e ct.Event
	// For wp set where region is partially tainted:
	// The offset and sz of tainted region in watch region
	taint_offset int
	taint_sz     uint64
	// If type is Fake, ignore all logged events after this, until the last `tail` events in the log
	tail int
}

// Whether event was already seen (ignoring lineno, since e.g. watchpoint may be re-set on diff line)
func dupEvent(all_actual []ct.Event, actual_i int, actual ct.Event) bool {
	opt := cmp.FilterPath(func(p cmp.Path) bool {
		vx := p.Last().String()
		return vx == ".Line"
	}, cmp.Ignore())

	for i, other := range all_actual {
		if i == actual_i {
			return false // stop when reach cur event
		}
		if diff := cmp.Diff(other, actual, opt); diff == "" {
			return true
		}
	}
	return false
}

func checkEvents(t *testing.T, expected []TestEvent, event_log string, testcfg *TestConfig) {
	file, err := os.Open(event_log)
	assertNoError(err, t, "open event log")
	defer file.Close()
	r := csv.NewReader(file)

	_, err = r.Read() // read header
	assertNoError(err, t, "read header")
	ignoreDups := testcfg == nil || !testcfg.checkDupEvents

	events, err := ct.ReadEventLog(event_log)
	assertNoError(err, t, "read event log")
	// Hits/dups are present in actual but not expected => indices are not 1:1
	expected_i := 0
	actual_i := 0

	// 1. Check actual events within range of expected
	for ; actual_i < len(events); actual_i++ {
		actual := events[actual_i]

		if expected_i > len(expected)-1 {
			break
		}

		// 1a. Last fake event to ignore (i.e. treat next event as normal)
		if expected[expected_i].e.EventType == ct.Fake {
			stop_ignoring_fake := actual_i == len(events)-expected[expected_i].tail-1
			if stop_ignoring_fake {
				expected_i++
			}
		}

		// 1b. Ignore if applicable
		if expected[expected_i].e.EventType == ct.Fake ||
			(ignoreDups && dupEvent(events, actual_i, actual)) ||
			actual.EventType == ct.WatchpointHit {
			// Ignore wp hits for now. Might be useful to test in some cases
			// (i.e. if hit doesn't cause a new wp to be set in this case, but could in other cases), but
			// annoying to figure out ground truth - whether/how many hits on a line depends on exactly how it compiles.
			// Ignore
			continue
		}

		// 1c. Check event
		if actual.EventType == ct.WatchpointSet {
			// Check wp set (minus address, which is unpredictable) - use address to fill in expected m-c map updates
			expected_wp := expected[expected_i]
			assertEventsEqual(t, expected_wp.e, actual, fmt.Sprintf("expected event %v (actual i %v) wrong", expected_i, actual_i), true)

			offset := 0
			// Fill in m-c map
			taint_addr := actual.Address + uint64(expected_wp.taint_offset)
			for addr := taint_addr; addr < taint_addr+expected_wp.taint_sz; addr++ {
				memparam_idx := expected_i + offset + 1
				if memparam_idx > len(expected)-1 {
					// went past last event
					break
				}
				e := &(expected[memparam_idx].e)
				assertEqual(t, ct.MemParamMapUpdate, e.EventType, fmt.Sprintf("expected m-p update after wp set at event %v", expected_i))
				e.Address = addr
				offset++
			}
		} else if actual.EventType == ct.MessageRecv || actual.EventType == ct.ConfigLoad {
			// Don't know what message recv buffer address to expect - but use it to fill in expected wp set address
			assertEventsEqual(t, expected[expected_i].e, actual, fmt.Sprintf("expected event %v wrong", expected_i), true)

			expected_wp_set := &expected[expected_i+1].e
			assertEqual(t, ct.WatchpointSet, expected_wp_set.EventType, fmt.Sprintf("expected wp set after recv at event %v", expected_i))
			expected_wp_set.Address = actual.Address
			actual_wp_set := events[expected_i+1]
			// Check wp set now since above logic will ignore addr
			assertEventsEqual(t, *expected_wp_set, actual_wp_set, fmt.Sprintf("expected event %v wrong", expected_i+1), false)
		} else if actual.EventType == ct.MemParamMapUpdate || actual.EventType == ct.BehaviorMapUpdate {
			assertEventsEqual(t, expected[expected_i].e, actual, fmt.Sprintf("expected event %v wrong", expected_i), false)
		} else if actual.EventType == ct.MessageSend {
			// Don't know what message send buffer address to expect
			assertEventsEqual(t, expected[expected_i].e, actual, fmt.Sprintf("expected event %v wrong", expected_i), true)
		} else {
			t.Fatalf("Unhandled event type: %+v\n", actual)
		}
		expected_i++
	}

	// 2. Check all expected events occurred
	assertEqual(t, len(expected), expected_i,
		fmt.Sprintf("expected event(s) didn't happen: expected %v, got %v", len(expected), expected_i))

	// 3. Check no unexpected events occurred
	for ; actual_i < len(events); actual_i++ {
		actual := events[actual_i]
		ignore := (ignoreDups && dupEvent(events, actual_i, actual)) ||
			actual.EventType == ct.WatchpointHit

		if !ignore {
			t.Fatalf("Unexpected event happened: %+v\n", actual)
		}
	}
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
