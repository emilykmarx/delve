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

func behavior() ct.BehaviorValue {
	return ct.BehaviorValue{Offset: 1, Send_endpoint: "send_endpoint", Recv_endpoint: "recv_endpoint", Transport: "tcp", Send_module: "send_module"}
}

// Checks .gv
func checkGraph(t *testing.T, behavior_maps []string, graph_file string, expected_lines []string) {
	if os.Getenv("CT_KEEP_CSVS") == "" {
		graph_file = filepath.Join(t.TempDir(), graph_file)
	}
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
	send_behavior := behavior()
	send_tainting_vals := ct.MakeTaintingVals(&send_param, nil)

	send_behavior_map := ct.BehaviorMap{send_behavior: send_tainting_vals}
	// tainted ones are reachable => should be combined with sender's node
	recv_tainted := send_behavior
	recv_tainted.Send_module = ""
	recv_tainted.Recv_module = "recv_module"
	// untainted ones are unreachable => should be removed
	recv_untainted := recv_tainted
	recv_untainted.Offset = recv_tainted.Offset + 1

	send_tainted := ct.BehaviorValue{Offset: 1, Send_endpoint: "send_endpoint_2", Recv_endpoint: "recv_endpoint_2", Transport: "tcp", Send_module: "recv_module"}
	send_untainted := send_tainted
	send_untainted.Offset = send_tainted.Offset + 1

	tainting_vals := ct.MakeTaintingVals(nil, &ct.TaintingBehavior{Behavior: recv_tainted, Flow: ct.DataFlow})
	recv_behavior_map := ct.BehaviorMap{send_tainted: tainting_vals, send_untainted: tainting_vals}
	tainting_vals = ct.MakeTaintingVals(nil, &ct.TaintingBehavior{Behavior: recv_untainted, Flow: ct.DataFlow})
	recv_behavior_map[send_untainted] = tainting_vals

	send_file := "fake_send_map.csv"
	recv_file := "fake_recv_map.csv"
	if os.Getenv("CT_KEEP_CSVS") == "" {
		send_file = filepath.Join(t.TempDir(), send_file)
		recv_file = filepath.Join(t.TempDir(), recv_file)
	}
	assertNoError(ct.WriteBehaviorMap(send_file, send_behavior_map), t, "write")
	assertNoError(ct.WriteBehaviorMap(recv_file, recv_behavior_map), t, "write")

	expected_lines := []string{
		"strict digraph {",
		"\"{ {param_module file param} {0     }}\" [  weight=0 ];",
		"\"{ {param_module file param} {0     }}\" -> \"{ {  } {1 send_endpoint recv_endpoint tcp  }}\" [ EdgeType=\"Control Flow\",  weight=0 ];",
		"\"{ {  } {1 send_endpoint recv_endpoint tcp  }}\" [  weight=0 ];",
		"\"{ {  } {1 send_endpoint recv_endpoint tcp  }}\" -> \"{ {  } {1 send_endpoint_2 recv_endpoint_2 tcp  }}\" [ EdgeType=\"Data Flow\",  weight=0 ];",
		"\"{ {  } {1 send_endpoint_2 recv_endpoint_2 tcp  }}\" [  weight=0 ];",
		"}",
	}
	checkGraph(t, []string{send_file, recv_file}, "fake_graph.gv", expected_lines)
}

func readWriteBehaviorMap(t *testing.T, behavior_map ct.BehaviorMap) {
	file := filepath.Join(t.TempDir(), "behavior_map.csv")
	assertNoError(ct.WriteBehaviorMap(file, behavior_map), t, "write")
	behavior_map_2, err := ct.ReadBehaviorMap(file)
	assertNoError(err, t, "read")

	// Check equality (and that read/write worked)
	if diff := cmp.Diff(behavior_map, behavior_map_2); diff != "" {
		t.Fatalf("Map before read != after\nDiff: %v\nBefore: %v\nAfter: %v",
			diff, behavior_map, behavior_map_2)
	}
}

// Check behavior map read/write to file, and equality operations on it
func TestReadWriteBehaviorMap(t *testing.T) {
	tainting_param := taintingParam()
	behavior := behavior()
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
	// 1. Set wp for config[0]
	initial_line := 10
	config := Config("control_flow.go", "config[0]", initial_line)

	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(1), initial_line, ct.DataFlow, nil, nil)

	// 2. Hit wp in if condition => propagate to maybe_tainted
	expected_events = append(expected_events,
		watchpointSet(&config, "maybe_tainted", 3, 19, ct.ControlFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "maybe_tainted_2", 1, 22, ct.ControlFlow, nil, nil)...)

	dataflow_taint := ct.TaintingParam{
		Param: ct.Param{
			Module: config.Module,
			Param:  config.Initial_watchexpr,
		},
		Flow: ct.DataFlow,
	}
	expected_events = append(expected_events,
		watchpointSet(&config, "regular", 1, 23, ct.ControlFlow, &dataflow_taint, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "maybe_tainted_3", 1, 32, ct.ControlFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "maybe_tainted_4", 1, 39, ct.ControlFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "maybe_tainted_5", 5, 43, ct.ControlFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "i", 1, 49, ct.ControlFlow, nil, nil)...)

	expected_events = append(expected_events,
		watchpointSet(&config, "j", 1, 50, ct.DataFlow, nil, nil)...)

	run(t, &config, expected_events)
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

	run(t, &config, expected_events)
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

	run(t, &config, expected_events)
}

func TestStrings(t *testing.T) {
	initial_line := 15
	config := Config("strings.go", "s", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(2), initial_line, ct.DataFlow, nil, nil)

	expected_events = append(expected_events,
		ct.Event{EventType: ct.WatchpointSet, Size: 6, Expression: "s2", Line: 16})

	tainting_param := configTaintingParam(&config, ct.DataFlow)
	tainting_vals := ct.TaintingVals{Params: tainting_param}
	// Need to fix partial taint - currently taints first two bytes of s2, but should be last two
	for offset := 0; offset < 2; offset++ {
		expected_events = append(expected_events,
			ct.Event{EventType: ct.MemParamMapUpdate, Size: 1, TaintingVals: &tainting_vals, Line: 16})
	}

	expected_events = append(expected_events,
		watchpointSet(&config, "i", uint64(1), 19, ct.DataFlow, nil, nil)...)

	run(t, &config, expected_events)
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

	run(t, &config, expected_events)
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
	run(t, &config, expected_events)

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
	run(t, &config, expected_events)

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
	run(t, &config, expected_events)
}

func TestMethods(t *testing.T) {
	initial_line := 39
	config := Config("methods.go", "nested.name.Data", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(2), initial_line, ct.DataFlow, nil, nil)

	expected_events = append(expected_events,
		watchpointSet(&config, "recvr_callee.Data", uint64(2), 27, ct.DataFlow, nil, nil)...)

	run(t, &config, expected_events)
}

func TestFuncLitGoRoutine(t *testing.T) {
	// Compiler uses same memory for chars of both fqdn strings,
	// so only expect wp for chars on 13
	initial_line := 14
	config := Config("funclit_goroutine.go", "fqdn", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(4), initial_line, ct.DataFlow, nil, nil)
	run(t, &config, expected_events)
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

	run(t, &config, expected_events)
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

	run(t, &config, expected_events)
}

func TestCasts(t *testing.T) {
	initial_line := 11
	config := Config("casts.go", "x", initial_line)
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(8), initial_line, ct.DataFlow, nil, nil)

	expected_events = append(expected_events,
		watchpointSet(&config, "y", uint64(8), 13, ct.DataFlow, nil, nil)...)

	run(t, &config, expected_events)
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
	extra_tainting_param *ct.TaintingParam, extra_tainting_behavior *ct.TaintingBehavior) []ct.Event {
	// Watchpoint set
	events := []ct.Event{
		{EventType: ct.WatchpointSet, Size: sz, Expression: watchexpr, Line: line},
	}

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
		events = append(events, ct.Event{
			// run() will fill in address from wp set
			EventType: ct.MemParamMapUpdate, Size: 1, TaintingVals: &tainting_vals, Line: line,
		})
	}
	return events
}

// If config passed: config.Initial_watchexpr taints the region of message specified by taint_start:taint_end.
// Msg buf sz is `sz`.
// If extra behavior is passed, add that to corresponding taint_sz bytes of sent message (starting with
// extra[Offset] and send_msg[Offset])
// Return resulting message send and behavior update events.
func messageSend(config *ct.Config, sent_msg ct.BehaviorValue, sz uint64, taint_sz uint64,
	extra_tainting_behavior *ct.TaintingBehavior) []ct.Event {
	sent_taint_start := sent_msg.Offset
	sent_msg.Offset = 0
	// Message send
	events := []ct.Event{
		{EventType: ct.MessageSend, Size: sz, Behavior: &sent_msg, Line: syscall_entry_line},
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
		events = append(events, ct.Event{
			EventType: ct.BehaviorMapUpdate, Size: 1, Behavior: &sent_msg_copy, TaintingVals: &tainting_vals, Line: syscall_entry_line},
		)
		i++
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

	readbufsz := uint64(512) // ReadFile uses buf of this size for smaller files
	config_load := ct.Event{
		EventType:    ct.ConfigLoad,
		Size:         readbufsz,
		TaintingVals: &tainting_vals,
		Line:         syscall_entry_line,
	}
	expected_events := []ct.Event{config_load}
	// Two read syscalls: one reads whole file, second advances buf pointer and reads nothing (EOF)
	expected_events = append(expected_events,
		watchpointSet(nil, ct.SyscallRecvBuf, readbufsz, syscall_entry_line, ct.DataFlow, &tainting_param, nil)...)

	readbufsz -= uint64(len(config_params))
	config_load.Size = readbufsz
	expected_events = append(expected_events, config_load)
	expected_events = append(expected_events,
		watchpointSet(nil, ct.SyscallRecvBuf, readbufsz, syscall_entry_line, ct.DataFlow, &tainting_param, nil)...)

	// bytes2
	sz := uint64(13)
	expected_events = append(expected_events,
		ct.Event{EventType: ct.WatchpointSet, Size: sz, Expression: "bytes2", Line: 24})

	param := "param1"
	tainting_param.Param.Param = param
	for offset := uint64(0); offset < sz; offset++ {
		if offset == 6 {
			// \n
			tainting_param.Param.Param = ""
		} else if offset > 6 {
			param = "param2"
			tainting_param.Param.Param = param
		}
		tainting_vals := ct.MakeTaintingVals(&tainting_param, nil)
		expected_events = append(expected_events, ct.Event{
			EventType: ct.MemParamMapUpdate, Size: 1, TaintingVals: &tainting_vals, Line: 24,
		})
	}

	// param1_var
	param = "param1"
	tainting_param.Param.Param = param
	expected_events = append(expected_events,
		watchpointSet(nil, "param1_var", uint64(len(param)), 26, ct.DataFlow, &tainting_param, nil)...)

	// The usual syntax for passing args from dlv to target doesn't work in test
	os.Setenv("config", target_config_file)
	run(t, &config, expected_events)
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
		Send_endpoint: client_endpoint,
		Recv_endpoint: server_endpoint,
		Transport:     "tcp",
		Send_module:   client_config.Module,
	}
	expected_events :=
		watchpointSet(&client_config, client_config.Initial_watchexpr, uint64(1), initial_line, ct.DataFlow, nil, nil)

	expected_events = append(expected_events, messageSend(&client_config, sent_msg, 6, 1, nil)...)
	go run(t, &client_config, expected_events)

	// RECEIVER
	server_config := Config("behavior_server.go", "", 0)
	server_config.Module = "recv_module"
	server_config.Event_log_filename = server_config.Module + "_event_log.csv"
	server_config.Behavior_map_filename = server_config.Module + "_behavior_map.csv"
	server_config.Server_endpoint = "localhost:4041"

	recvd_msg := ct.BehaviorValue{
		Send_endpoint: client_endpoint,
		Recv_endpoint: server_endpoint,
		Transport:     "tcp",
		Recv_module:   server_config.Module,
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

	sent_msg = ct.BehaviorValue{
		Offset:        1,
		Send_endpoint: server_endpoint,
		Recv_endpoint: client_endpoint,
		Transport:     "tcp",
		Send_module:   server_config.Module,
	}
	tainting_behavior.Behavior.Offset = 0 // msg_B[1] tainted by msg_A[0] (messageSend takes care of rest of msg_B)
	expected_events = append(expected_events, messageSend(nil, sent_msg, 3, 2, &tainting_behavior)...)

	run(t, &server_config, expected_events)

	expected_lines := []string{
		"strict digraph {",
		"\"{ {send_module  config[1]} {0     }}\" [  weight=0 ];",
		"\"{ {send_module  config[1]} {0     }}\" -> \"{ {  } {1 127.0.0.1:5050 127.0.0.1:6060 tcp  }}\" [ EdgeType=\"Data Flow\",  weight=0 ];",
		"\"{ {  } {1 127.0.0.1:5050 127.0.0.1:6060 tcp  }}\" [  weight=0 ];",
		"\"{ {  } {1 127.0.0.1:5050 127.0.0.1:6060 tcp  }}\" -> \"{ {  } {2 127.0.0.1:6060 127.0.0.1:5050 tcp  }}\" [ EdgeType=\"Data Flow\",  weight=0 ];",
		"\"{ {  } {2 127.0.0.1:6060 127.0.0.1:5050 tcp  }}\" [  weight=0 ];",
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

	run(t, &config, expected_events)
}

func TestAllocatorHTTP(t *testing.T) {
	initial_line := 27
	config := Config("allocator_http.go", "*ptr", initial_line)
	config.Move_wps = true
	expected_events :=
		watchpointSet(&config, config.Initial_watchexpr, uint64(8), initial_line, ct.DataFlow, nil, nil)

	expected_events = append(expected_events,
		watchpointSet(&config, "x", uint64(8), 31, ct.DataFlow, nil, nil)...)

	run(t, &config, expected_events)
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
		t.Fatalf("Delve server failed to start listening; stdout %v", string(stdout.savedOutput))
	}

	// Check for error
	// XXX fix this for logging in my fork of go
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
// Note this may be called concurrently for multiple modules.
// TODO (minor) prefix log msgs with module to make clearer for tests that run multiple modules
// Note Fatalf shouldn't be called here - use Fail() instead (since it's called from goroutine)
func run(t *testing.T, config *ct.Config, expected_events []ct.Event) {
	// Set up config
	config.Initial_bp_file = filepath.Join(protest.FindFixturesDir(), "conftamer", config.Initial_bp_file)
	if config.Initial_watchexpr != "" {
		config.Initial_bp_line = expected_events[0].Line
	}

	if os.Getenv("CT_KEEP_CSVS") == "" {
		event_log := filepath.Join(t.TempDir(), config.Event_log_filename)
		behavior_map := filepath.Join(t.TempDir(), config.Behavior_map_filename)
		config.Event_log_filename = event_log
		config.Behavior_map_filename = behavior_map
	}

	config_file := filepath.Join(t.TempDir(), "client_config.yml")
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
	path, target_go, err := protest.SetGoVersion()
	assertNoError(err, t, "set go version")
	defer func() {
		protest.UnSetGoVersion(path, target_go)
	}()

	assertNoError(server.Start(), t, "start headless instance")
	waitForServer(t, &server_out, &server_err)

	// Run dlv client until exit or timeout
	client_timeout := 10 * time.Second
	ctx, cancel = context.WithTimeout(context.Background(), client_timeout)
	defer cancel()

	client := exec.CommandContext(ctx, client_bin, "-config="+config_file)
	t.Logf("Starting client with timeout %v: %v\n", client_timeout, strings.Join(client.Args, " "))

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
}

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
	// All actual events are as expected
	for _, actual := range events {
		if actual.EventType == ct.WatchpointSet {
			// Don't know what watchpoint address to expect - but use it to fill in expected m-c map updates
			assertEventsEqual(t, expected[expected_i], actual, fmt.Sprintf("expected event %v wrong", expected_i), true)

			offset := 0
			// Assumes newly watched region is tainted from the beginning, possibly ending before the end
			for addr := actual.Address; addr < actual.Address+actual.Size; addr++ {
				e := &expected[expected_i+offset+1]
				if e.EventType != ct.MemParamMapUpdate {
					// Rest of newly watched region isn't tainted (strings test)
					break
				}
				assertEqual(t, ct.MemParamMapUpdate, e.EventType, fmt.Sprintf("expected m-p update after wp set at event %v", expected_i))
				e.Address = addr
				offset++
			}
		} else if actual.EventType == ct.MessageRecv || actual.EventType == ct.ConfigLoad {
			// Don't know what message recv buffer address to expect - but use it to fill in expected wp set address
			assertEventsEqual(t, expected[expected_i], actual, fmt.Sprintf("expected event %v wrong", expected_i), true)

			expected_wp_set := &expected[expected_i+1]
			assertEqual(t, ct.WatchpointSet, expected_wp_set.EventType, fmt.Sprintf("expected wp set after recv at event %v", expected_i))
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

	// All expected events occurred
	assertEqual(t, len(expected), expected_i, "expected event(s) didn't happen")
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
