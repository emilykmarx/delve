package main_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	protest "github.com/go-delve/delve/pkg/proc/test"
)

// Build client
func getClientBin(t *testing.T) string {
	clientbin := filepath.Join(t.TempDir(), "client.exe")
	args := []string{"build", "-o", clientbin}
	args = append(args, "github.com/go-delve/delve/cmd/dlv/dlv_config_client")

	out, err := exec.Command("go", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("go build -o %v github.com/go-delve/delve/cmd/dlv/dlv_config_client: %v\n%s", clientbin, err, string(out))
	}

	return clientbin
}

// Tests clear when another sw wp still exists on same page
func TestCallAndAssign1(t *testing.T) {
	expected_logs := []expectedLog{
		{kind: CreateWatchpoint, lineno: 31, watchexpr: "stack"},
		{kind: CreateWatchpoint, lineno: 35, watchexpr: "spacer"},
		{kind: CreateWatchpoint, lineno: 15, watchexpr: "tainted_param"},
		{kind: CreateWatchpoint, lineno: 21, watchexpr: "tainted_param_2"},
		{kind: CreateWatchpoint, lineno: 42, watchexpr: "y"},
		{kind: CreateWatchpoint, lineno: 46, watchexpr: "z"},
	}
	run(t, "call_assign_1.go", expected_logs, nil)
}

func TestCallAndAssign2(t *testing.T) {
	expected_logs := []expectedLog{
		{kind: CreateWatchpoint, lineno: 19, watchexpr: "stack"},
		{kind: CreateWatchpoint, lineno: 10, watchexpr: "tainted_param_2"},
		{kind: CreateWatchpoint, lineno: 22, watchexpr: "a"},
	}
	run(t, "call_assign_2.go", expected_logs, nil)
}

func TestStrings(t *testing.T) {
	expected_logs := []expectedLog{
		{kind: CreateWatchpoint, lineno: 15, watchexpr: "s"},
		{kind: CreateWatchpoint, lineno: 16, watchexpr: "s2"},
		{kind: CreateWatchpoint, lineno: 19, watchexpr: "i"},
	}
	run(t, "strings.go", expected_logs, nil)
}

func TestSliceRangeBuiltins(t *testing.T) {
	expected_logs := []expectedLog{
		// Slice of strings => set on each string
		{kind: CreateWatchpoint, lineno: 14, watchexpr: "conf.search[0]"},
		{kind: CreateWatchpoint, lineno: 14, watchexpr: "conf.search[1]"},
		{kind: CreateWatchpoint, lineno: 22, watchexpr: "names[0]"},
		{kind: CreateWatchpoint, lineno: 22, watchexpr: "names[1]"},
	}
	// Client sets initial watch on conf.search => server sets wp on both strings
	initial_watchexpr := "conf.search"
	run(t, "slice_range_builtins.go", expected_logs, &initial_watchexpr)
}

// Slice of slices, array of slices/strings (slice of strings is in TestSliceRangeBuiltins)
// Note that this test checks the watchexpr, so it's important how the server chooses to set it -
// does so when (t *Target) SetWatchpoint calls SetWatchpointNoEval instead of telling the
// Debugger to recurse (i.e. get to a string or slice/array of non-references)
func TestReferenceElems(t *testing.T) {
	dir := "reference_elems/"

	// Array of strings => set on each string
	expected_logs := []expectedLog{
		{kind: CreateWatchpoint, lineno: 10, watchexpr: "arr_strs[0]"},
		{kind: CreateWatchpoint, lineno: 10, watchexpr: "arr_strs[1]"},
	}
	initial_watchexpr := "arr_strs"
	run(t, dir+"arr_strs.go", expected_logs, &initial_watchexpr)

	// Array of slices => set on each slice's strings
	expected_logs = []expectedLog{
		{kind: CreateWatchpoint, lineno: 12, watchexpr: "arr_slices[0][0]"},
		{kind: CreateWatchpoint, lineno: 12, watchexpr: "arr_slices[0][1]"},
		{kind: CreateWatchpoint, lineno: 12, watchexpr: "arr_slices[1][0]"},
		{kind: CreateWatchpoint, lineno: 12, watchexpr: "arr_slices[1][1]"},
	}
	initial_watchexpr = "arr_slices"
	run(t, dir+"arr_slices.go", expected_logs, &initial_watchexpr)

	// Slice of slices => set on each inner slice's strings
	expected_logs = []expectedLog{
		{kind: CreateWatchpoint, lineno: 12, watchexpr: "slice_slices[0][0]"},
		{kind: CreateWatchpoint, lineno: 12, watchexpr: "slice_slices[0][1]"},
		{kind: CreateWatchpoint, lineno: 12, watchexpr: "slice_slices[1][0]"},
		{kind: CreateWatchpoint, lineno: 12, watchexpr: "slice_slices[1][1]"},
	}
	initial_watchexpr = "slice_slices"
	run(t, dir+"slice_slices.go", expected_logs, &initial_watchexpr)
}

func TestMethods(t *testing.T) {
	expected_logs := []expectedLog{
		{kind: CreateWatchpoint, lineno: 39, watchexpr: "nested.name.Data"},
		{kind: CreateWatchpoint, lineno: 27, watchexpr: "recvr_callee.Data"},
	}

	run(t, "methods.go", expected_logs, nil)
}

func TestFuncLitGoRoutine(t *testing.T) {
	// Compiler uses same memory for chars of both fqdn strings,
	// so only expect wp for chars on 13
	expected_logs := []expectedLog{
		{kind: CreateWatchpoint, lineno: 14, watchexpr: "fqdn"},
	}
	run(t, "funclit_goroutine.go", expected_logs, nil)
}

func TestMultiRound(t *testing.T) {
	expected_logs := []expectedLog{
		{kind: CreateWatchpoint, lineno: 11, watchexpr: "vars[0]"},
		{kind: CreateWatchpoint, lineno: 16, watchexpr: "vars[i]"},
		{kind: CreateWatchpoint, lineno: 16, watchexpr: "vars[i]"},
		{kind: CreateWatchpoint, lineno: 16, watchexpr: "vars[i]"},
		{kind: CreateWatchpoint, lineno: 16, watchexpr: "vars[i]"},
		{kind: CreateWatchpoint, lineno: 16, watchexpr: "vars[i]"},
	}

	run(t, "multiround.go", expected_logs, nil)
}

func TestRuntimeHits(t *testing.T) {
	expected_logs := []expectedLog{
		{kind: CreateWatchpoint, lineno: 21, watchexpr: "name"},
		// uses same backing array for name and name_callee, but n.Data and n_caller.Data each have their own
		{kind: CreateWatchpoint, lineno: 16, watchexpr: "n.Data[:]"},
		{kind: CreateWatchpoint, lineno: 22, watchexpr: "n_caller.Data"},
	}

	run(t, "runtime_hits.go", expected_logs, nil)
}

func TestCasts(t *testing.T) {
	expected_logs := []expectedLog{
		{kind: CreateWatchpoint, lineno: 11, watchexpr: "x"},
		{kind: CreateWatchpoint, lineno: 13, watchexpr: "y"},
	}

	run(t, "casts.go", expected_logs, nil)
}

func TestNetworkSend(t *testing.T) {
	expected_logs := []expectedLog{
		{kind: CreateWatchpoint, lineno: 11, watchexpr: "buf"},
		{kind: TaintedMsg},
	}

	run(t, "network_send.go", expected_logs, nil)
}
func TestStructs(t *testing.T) {
	expected_logs := []expectedLog{
		{kind: CreateWatchpoint, lineno: 26, watchexpr: "arr"},
		{kind: CreateWatchpoint, lineno: 27, watchexpr: "struct_lit.Data"},
		{kind: CreateWatchpoint, lineno: 29, watchexpr: "s.Data"},
		{kind: CreateWatchpoint, lineno: 20, watchexpr: "s_callee.Data"},
		// s.callee OOS
		{kind: CreateWatchpoint, lineno: 31, watchexpr: "s_caller.Data"},
		{kind: CreateWatchpoint, lineno: 36, watchexpr: "multiline_lit.Data"},
		{kind: CreateWatchpoint, lineno: 41, watchexpr: "nested.name.Data"},
		{kind: CreateWatchpoint, lineno: 44, watchexpr: "nested2.name.Data"},
	}
	run(t, "structs.go", expected_logs, nil)
}

/* TODO need to investigate this - per asm, doesn't seem like should be fake...
func TestFakeArg(t *testing.T) {
	expected_logs := []expectedLog{
		{kind: CreateWatchpoint, lineno: 13, watchexpr: "a"},
		{kind: CreateWatchpoint, lineno: 6, watchexpr: "addrs"},
	}

	run(t, "fake_xv.go", expected_logs)
}
*/

// Not fully automated, but here for convenience.
// (Need to manually run xenon, then place outfiles in ./dlv_config_client/xenon_out/)
// Due to non-determinism (concurrency, realloc from append), may require tweaking for some runs.
// These linenos are correct for go1.20.1 fb06acf5, xenon e57b72b
func TestXenon_single_query(t *testing.T) {
	// Server makes a single DNS query (type A), then exits (after Ping fails)
	expected_logs := []expectedLog{
		// conf.search only has one string with this resolv.conf
		// names has 2 strings (eecs and localhost.)

		// dnsReadConfig()- dnsclient_unix.go
		{kind: CreateWatchpoint, lineno: 144, watchexpr: "conf.search[0]"},

		// (*dnsConfig).nameList() - dnsclient_unix.go
		{kind: CreateWatchpoint, lineno: 522, watchexpr: "names[0]"},

		// dnsmessage.NewName() - message.go
		{kind: CreateWatchpoint, lineno: 1907, watchexpr: "n.Data[:]"},

		// (*Resolver).tryOneName() - dnsclient_unix.go
		{kind: CreateWatchpoint, lineno: 268, watchexpr: "n.Data"},
		{kind: CreateWatchpoint, lineno: 277, watchexpr: "q.Name.Data"},

		// (*Resolver).exchange() - dnsclient_unix.go
		{kind: CreateWatchpoint, lineno: 166, watchexpr: "q.Name.Data"},

		// newRequest() - dnsclient_unix.go
		{kind: CreateWatchpoint, lineno: 60, watchexpr: "q.Name.Data"},

		// (*Builder).Question() - message.go
		{kind: CreateWatchpoint, lineno: 1324, watchexpr: "q.Name.Data"},

		// (*Name).pack - message.go
		{kind: CreateWatchpoint, lineno: 1971, watchexpr: "msg"},

		// dnsPacketRoundTrip - dnsclient_unix.go
		{kind: CreateWatchpoint, lineno: 106, watchexpr: "query.Name.Data"},
	}

	/*
			 dlv exec --headless --api-version=2 --accept-multiclient --listen=:4040 \
		     /go/src/github.com/radondb/xenon/bin/xenon -- -c /etc/xenon/xenon.json \
		     > server_out.txt 2> server_err.txt
		 dlv_config_client -initial_bp_file=/usr/local/go/src/net/dnsconfig_unix.go -initial_bp_line=144 -initial_watchexpr=conf.search \
		      > client_out.txt 2> client_err.txt
	*/

	files := []string{"client_err.txt", "server_err.txt", "client_out.txt", "server_out.txt"}
	outs := make([][]byte, len(files))
	for i, file := range files {
		out, err := os.ReadFile("dlv_config_client/xenon_out/" + file)
		if _, ok := err.(*os.PathError); ok {
			t.Skipf("Missing xenon log file %v", file)
		}
		assertNoError(err, t, "open Xenon file")
		outs[i] = out
	}

	checkStderr(t, outs[0], outs[1])
	checkStdout(t, outs[3], expected_logs, "conf.search")
}

func waitForServer(t *testing.T, stdout *saveOutput, stderr *saveOutput) {
	// Wait for server to start
	for ; len(stdout.savedOutput) == 0; time.Sleep(300 * time.Millisecond) {
	}
	if !strings.HasPrefix(string(stdout.savedOutput), "API server listening at:") {
		t.Fatalf("Delve server failed to start listening")
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

// Expect to set watchpoints for watchexprs on corresponding lines
// Client's initial watchexpr is one in the first expected_log,
// unless initial_watchexpr is passed
func run(t *testing.T, testfile string, expected_logs []expectedLog, initial_watchexpr *string) {
	// Start dlv server
	listenAddr := "localhost:4040"
	fixturePath := filepath.Join(protest.FindFixturesDir(), "dlv_config_client", testfile)
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
	init_watchexpr := expected_logs[0].watchexpr
	if initial_watchexpr != nil {
		init_watchexpr = *initial_watchexpr
	}
	client := exec.CommandContext(ctx, getClientBin(t),
		"-initial_bp_file="+fixturePath, fmt.Sprintf("-initial_bp_line=%v", expected_logs[0].lineno),
		"-initial_watchexpr="+init_watchexpr)

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
	checkStdout(t, client_out.savedOutput, expected_logs, init_watchexpr)
}

func checkStderr(t *testing.T, client_err []byte, server_err []byte) {
	// Check for errors during replay
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
}

type LogType string

const (
	CreateWatchpoint LogType = "CreateWatchpoint"
	TaintedMsg       LogType = "SendTaintedMessage"
)

// A log message about a watchpoint
type expectedLog struct {
	kind      LogType
	lineno    int
	watchexpr string
	// to be filled in
	watchaddr uint64
}

func checkStdout(t *testing.T, stdout []byte, expected_logs []expectedLog, initial_watchexpr string) {
	watchexpr_fmt := "%s lineno %d watchexpr %s watchaddr 0x%x"
	next_wp_log := 0         // index of the next log we expect to see
	expect_memparam := false // whether we expect to see a memory-parameter update next
	mem_param_fmt := "\tMemory-parameter map: 0x%x => {items:map[{param:%s flow:1}:{}]}\n"
	tainted_msg_fmt := string(TaintedMsg) + " {items:map[{param:%s flow:1}:{}]}"
	for _, line := range strings.Split(string(stdout), "\n") {
		var lineno int
		var watchexpr string
		var watchaddr uint64
		var kind string
		expected_log := expected_logs[next_wp_log]

		// Check for creating wps and updating mem-param map, in expected order
		if _, err := fmt.Sscanf(line, watchexpr_fmt, &kind, &lineno, &watchexpr, &watchaddr); err == nil {
			// CreateWatchpoint
			if expect_memparam {
				t.Fatalf("Client did not log expected update of memory-parameter map for %+v", expected_logs[next_wp_log-1])
			}
			expect_memparam = true
			assertEqual(t, expected_log.lineno, lineno, expected_log)
			assertEqual(t, expected_log.watchexpr, watchexpr, expected_log)
			expected_logs[next_wp_log].watchaddr = watchaddr
			next_wp_log++
		} else if _, err := fmt.Sscanf(line, mem_param_fmt, &watchaddr, &watchexpr); err == nil {
			// Memory-param map
			if !expect_memparam {
				t.Fatalf("Found unexpected memory-parameter map update: %v\n", line)
			}
			assertEqual(t, expected_logs[next_wp_log-1].watchaddr, watchaddr, expected_log)
			assertEqual(t, initial_watchexpr, watchexpr, expected_log) // all are tainted by initial_watchexpr
			expect_memparam = false
		} else if _, err := fmt.Sscanf(line, tainted_msg_fmt, &watchexpr); err == nil {
			// Tainted msg
			assertEqual(t, initial_watchexpr, watchexpr, expected_logs[next_wp_log]) // all are tainted by initial_watchexpr
			next_wp_log++
		}

		if next_wp_log == len(expected_logs) {
			// found all expected
			break
		}
	}

	assertEqual(t, len(expected_logs), next_wp_log, "not enough wp logs")

	// Check no unexpected wps were created
	n_logs := strings.Count(string(stdout), string(CreateWatchpoint)) + strings.Count(string(stdout), string(TaintedMsg))
	assertEqual(t, len(expected_logs), n_logs, "too many wp logs")

}
