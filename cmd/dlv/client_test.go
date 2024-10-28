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

// TODO add tests for runtime hits

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
	expected_logs := []expectedWpLog{
		{kind: CreateNonPending, lineno: 26, watchexpr: "stack"},
		{kind: CreateNonPending, lineno: 30, watchexpr: "spacer"},
		{kind: CreateNonPending, lineno: 11, watchexpr: "tainted_param"},
		{kind: CreateNonPending, lineno: 17, watchexpr: "tainted_param_2"},
		{kind: CreateNonPending, lineno: 37, watchexpr: "y"},
		{kind: CreateNonPending, lineno: 41, watchexpr: "z"},
	}
	run(t, "call_assign_1.go", expected_logs)
}

func TestCallAndAssign2(t *testing.T) {
	expected_logs := []expectedWpLog{
		{kind: CreateNonPending, lineno: 19, watchexpr: "stack"},
		{kind: CreateNonPending, lineno: 10, watchexpr: "tainted_param_2"},
		{kind: CreateNonPending, lineno: 22, watchexpr: "a"},
	}
	run(t, "call_assign_2.go", expected_logs)
}

func TestStrings(t *testing.T) {
	expected_logs := []expectedWpLog{
		{kind: CreateNonPending, lineno: 16, watchexpr: "s"},
		{kind: CreateNonPending, lineno: 16, watchexpr: "s[0]"},
		{kind: CreateNonPending, lineno: 17, watchexpr: "s2"},
		{kind: CreateNonPending, lineno: 17, watchexpr: "s2[0]"},
	}
	run(t, "strings.go", expected_logs)
}

func TestSliceRangeBuiltins(t *testing.T) {
	expected_logs := []expectedWpLog{
		{kind: CreateNonPending, lineno: 14, watchexpr: "conf.search"},
		{kind: CreateNonPending, lineno: 19, watchexpr: "suffix"},
		{kind: CreateNonPending, lineno: 19, watchexpr: "suffix[0]"},
		{kind: CreateNonPending, lineno: 22, watchexpr: "names"},
		{kind: CreateNonPending, lineno: 28, watchexpr: "names_caller"},
		{kind: CreateNonPending, lineno: 30, watchexpr: "names2"},
	}
	run(t, "slice_range_builtins.go", expected_logs)
}

func TestStructs(t *testing.T) {
	expected_logs := []expectedWpLog{
		{kind: CreateNonPending, lineno: 22, watchexpr: "arr[0]"},
		{kind: CreateNonPending, lineno: 23, watchexpr: "struct_lit.Data[0]"},
		{kind: CreateNonPending, lineno: 25, watchexpr: "s.Data[0]"},
		{kind: CreateNonPending, lineno: 16, watchexpr: "s_callee.Data[0]"},
		// s.callee OOS
		{kind: CreateNonPending, lineno: 27, watchexpr: "s_caller.Data[0]"},
	}
	run(t, "structs.go", expected_logs)
}

func TestArrays(t *testing.T) {
	expected_logs := []expectedWpLog{
		{kind: CreateNonPending, lineno: 10, watchexpr: "arr[0]"},
		{kind: CreateNonPending, lineno: 11, watchexpr: "s"},
	}
	run(t, "arrays.go", expected_logs)
}

func TestFuncLitGoRoutine(t *testing.T) {
	// Compiler uses same memory for chars of both fqdn strings,
	// so only expect wp for chars on 13
	expected_logs := []expectedWpLog{
		{kind: CreateNonPending, lineno: 14, watchexpr: "fqdn"},
		{kind: CreateNonPending, lineno: 14, watchexpr: "fqdn[0]"},
		{kind: CreateNonPending, lineno: 17, watchexpr: "fqdn"},
	}
	run(t, "funclit_goroutine.go", expected_logs)
}

func TestMultiRound(t *testing.T) {
	expected_logs := []expectedWpLog{
		{kind: CreateNonPending, lineno: 11, watchexpr: "vars[0]"},
		{kind: CreateNonPending, lineno: 16, watchexpr: "vars[i]"},
		{kind: CreateNonPending, lineno: 16, watchexpr: "vars[i]"},
		{kind: CreateNonPending, lineno: 16, watchexpr: "vars[i]"},
		{kind: CreateNonPending, lineno: 16, watchexpr: "vars[i]"},
		{kind: CreateNonPending, lineno: 16, watchexpr: "vars[i]"},
	}

	run(t, "multiround.go", expected_logs)
}

func TestRuntimeHits(t *testing.T) {
	expected_logs := []expectedWpLog{
		{kind: CreateNonPending, lineno: 21, watchexpr: "name"},
		{kind: CreateNonPending, lineno: 21, watchexpr: "name[0]"},
		{kind: CreateNonPending, lineno: 14, watchexpr: "name_callee"},
		// uses same mem for name[0] and name_callee[0]
		{kind: CreateNonPending, lineno: 16, watchexpr: "n.Data[0]"},
		{kind: CreateNonPending, lineno: 22, watchexpr: "n_caller.Data[0]"},
	}

	run(t, "runtime_hits.go", expected_logs)
}

/* Need to investigate this - per asm, doesn't seem like should be fake...
func TestFakeArg(t *testing.T) {
	expected_logs := []expectedWpLog{
		{kind: CreateNonPending, lineno: 13, watchexpr: "a"},
		{kind: CreateNonPending, lineno: 6, watchexpr: "addrs"},
	}

	run(t, "fake_xv.go", expected_logs)
}
*/

// TODO update for sw wp
// Not fully automated, but here for convenience.
// (Need to manually run xenon, then place outfiles in ./dlv_config_client/xenon_out/)
// Note there is concurrency, so it's technically possible this is a brittle test
// (assumes a certain ordering).
/*
func TestXenon_single_query(t *testing.T) {
	// Server makes a single DNS query (type A), then exits (after Ping fails)
	expected_logs := []expectedWpLog{
		// ROUND 1
		// dnsconfig_unix.go:dnsReadConfig()
		{kind: CreateNonPending, lineno: 144, watchexpr: "conf.search"},

		// dnsclient_unix.go:nameList()
		{kind: CreateNonPending, lineno: 510, watchexpr: "suffix"},
		{kind: CreateNonPending, lineno: 510, watchexpr: "suffix[0]"},
		{kind: CreateNonPending, lineno: 515, watchexpr: "names"},

		// OOS: suffix, names

		// dnsclient_unix.go:goLookupIPCNAMEOrder()
		{kind: CreateNonPending, lineno: 664, watchexpr: "fqdn"},
		{kind: CreateNonPending, lineno: 664, watchexpr: "fqdn[0]"},

		// dnsclient_unix.go:queryFn()
		{kind: RecordHWPending, lineno: 651, watchexpr: "fqdn"},
		// callee fqdn[0] re-uses caller mem

		// dnsclient_unix.go:responseFn()
		// interleaved w/ querying: Hit on 669 => set bp on 659 => hit 659
		{kind: RecordHWPending, lineno: 659, watchexpr: "fqdn"},
		// callee fqdn[0] re-uses caller mem

		// hit for fqdn[0] (via copy of name)
		{kind: RecordHWPending, lineno: 1907, watchexpr: "n.Data[0]"},

		// ROUND 2: Haven't done yet
	}

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

	checkOutput(t, outs[0], outs[1], outs[2], expected_logs)
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
// Passes first line and expr as initial ones for client
func run(t *testing.T, testfile string, expected_logs []expectedWpLog) {
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
	client := exec.CommandContext(ctx, getClientBin(t),
		"-initial_bp_file="+fixturePath, fmt.Sprintf("-initial_bp_line=%v", expected_logs[0].lineno),
		"-initial_watchexpr="+expected_logs[0].watchexpr)

	var client_out saveOutput
	var client_err saveOutput
	client.Stdout = &client_out
	client.Stderr = &client_err

	assertNoError(client.Run(), t, "run client")

	checkOutput(t, client_err.savedOutput, server_err.savedOutput, client_out.savedOutput, expected_logs)
}

func checkOutput(t *testing.T, client_err []byte, server_err []byte, client_out []byte, expected_logs []expectedWpLog) {
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
	checkWatchpoints(t, client_out, expected_logs)
}

type WpLogType string

const (
	CreateNonPending WpLogType = "CreateNonPending"
)

// A log message about a watchpoint
type expectedWpLog struct {
	kind      WpLogType
	lineno    int
	watchexpr string
	// to be filled in
	watchaddr uint64 // Can remove?
}

func checkWatchpoints(t *testing.T, stdout []byte, expected_logs []expectedWpLog) {
	// CreateNonPending
	watchexpr_fmt := "%s lineno %d watchexpr %s watchaddr 0x%x"
	next_wp_log := 0         // index of the next log we expect to see
	expect_memparam := false // whether we expect to see a memory-parameter update next
	mem_param_fmt := "\tMemory-parameter map: 0x%x => {params:map[{param:%s flow:1}:{}]}\n"
	for _, line := range strings.Split(string(stdout), "\n") {
		var lineno int
		var watchexpr string
		var watchaddr uint64
		var kind string
		expected_log := expected_logs[next_wp_log]

		// Check for creating wps and updating mem-param map, in expected order
		if _, err := fmt.Sscanf(line, watchexpr_fmt, &kind, &lineno, &watchexpr, &watchaddr); err == nil {
			if expect_memparam {
				t.Fatalf("Client did not log expected update of memory-parameter map for %+v", expected_logs[next_wp_log-1])
			}
			expect_memparam = true
			assertEqual(t, expected_log.lineno, lineno, expected_log)
			assertEqual(t, expected_log.watchexpr, watchexpr, expected_log)
			expected_logs[next_wp_log].watchaddr = watchaddr
			next_wp_log++
		} else if _, err := fmt.Sscanf(line, mem_param_fmt, &watchaddr, &watchexpr); err == nil {
			if !expect_memparam {
				t.Fatalf("Found unexpected memory-parameter map update: %v\n", line)
			}
			assertEqual(t, expected_logs[next_wp_log-1].watchaddr, watchaddr, expected_log)
			assertEqual(t, expected_logs[0].watchexpr, watchexpr, expected_log)
			expect_memparam = false
		}

		if next_wp_log == len(expected_logs) {
			// found all expected
			break
		}
	}

	assertEqual(t, len(expected_logs), next_wp_log, "not enough wp logs")

	// Check no unexpected wps were created
	n_wp_logs := strings.Count(string(stdout), string(CreateNonPending))
	assertEqual(t, len(expected_logs), n_wp_logs, "too many wp logs")

}
