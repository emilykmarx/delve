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

func TestCallAndAssign1(t *testing.T) {
	lines := []int{26, 30, 10, 16, 37, 41}
	watchexprs := []string{"stack", "spacer", "tainted_param", "tainted_param_2", "y", "z"}
	run(t, "call_assign_1.go", lines, watchexprs)
}

func TestCallAndAssign2(t *testing.T) {
	lines := []int{18, 9, 21}
	watchexprs := []string{"stack", "tainted_param_2", "a"}
	run(t, "call_assign_2.go", lines, watchexprs)
}

func TestStrings(t *testing.T) {
	lines := []int{13, 13, 14, 14}
	watchexprs := []string{"s", "s", "s2", "s2"}
	run(t, "strings.go", lines, watchexprs)
}

func TestStructSliceRangeBuiltins(t *testing.T) {
	lines := []int{11, 16, 16, 19, 25, 27}
	watchexprs := []string{"conf.search",
		"suffix", "suffix", // two for string
		"names", "names_caller", "names2"}
	run(t, "struct_slice_range_builtins.go", lines, watchexprs)
}

func TestFuncLitGoRoutine(t *testing.T) {
	lines := []int{13, 13, 16}
	// Compiler uses same memory for chars of both fqdn strings,
	// so only expect wp for chars on 13
	watchexprs := []string{"fqdn", "fqdn", "fqdn"}
	run(t, "funclit_goroutine.go", lines, watchexprs)
}

func TestMultiRound(t *testing.T) {
	lines := []int{8, 15, 15, 15, 15, 15}
	watchexprs := []string{"vars[0]", "vars[i]", "vars[i]", "vars[i]", "vars[i]", "vars[i]"}
	run(t, "multiround.go", lines, watchexprs)
}

// Return true to retry
func waitForReplay(t *testing.T, stdout *saveOutput, stderr *saveOutput) (time.Duration, bool) {
	start := time.Now()
	// Wait for output so can check error
	for ; len(stdout.savedOutput) == 0; time.Sleep(time.Second) {
	}
	if !strings.HasPrefix(string(stdout.savedOutput), "API server listening at:") {
		t.Fatalf("Delve server failed to start listening")
	}

	for {
		if len(stderr.savedOutput) > 0 {
			if strings.Contains(string(stderr.savedOutput), "check_working_counters()") {
				// perf counters in use => try again (should resolve shortly)
				return 0, true
			} else {
				t.Fatalf("Delve server errored while starting up")
			}
		}

		err := exec.Command("bash", "-c", "ps aux | grep 'rr replay' | grep -v grep").Run()
		if err != nil {
			if exiterr, ok := err.(*exec.ExitError); ok {
				if exiterr.ExitCode() == 1 {
					// No replay yet
					time.Sleep(time.Second)
				} else {
					t.Fatalf("Error in grep for replay: %v\n", err)
				}
			} else {
				t.Fatalf("Error in grep for replay: %v\n", err)
			}
		} else {
			// Found replay
			return time.Since(start), false
		}
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
func run(t *testing.T, testfile string, lines []int, watchexprs []string) {
	// Start dlv server, wait for it to finish recording
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
	var record_time time.Duration

	for retry := true; retry; {
		server := exec.CommandContext(ctx, getDlvBin(t), "debug", "--headless", "--backend=rr",
			"--api-version=2", "--accept-multiclient", "--listen", listenAddr, fixturePath)
		server_out = saveOutput{}
		server_err = saveOutput{}
		server.Stdout = &server_out
		server.Stderr = &server_err
		assertNoError(server.Start(), t, "start headless instance")
		record_time, retry = waitForReplay(t, &server_out, &server_err)
	}

	// Run dlv client until exit or timeout (assume replay time <= 3x record time)
	client_timeout := 3 * record_time
	t.Logf("Starting client with timeout %v\n", client_timeout)
	ctx, cancel = context.WithTimeout(context.Background(), client_timeout)
	defer cancel()
	client := exec.CommandContext(ctx, getClientBin(t),
		"-initial_bp_file="+fixturePath, fmt.Sprintf("-initial_bp_line=%v", lines[0]),
		"-initial_watchexpr="+watchexprs[0])

	var client_out saveOutput
	var client_err saveOutput
	client.Stdout = &client_out
	client.Stderr = &client_err

	assertNoError(client.Run(), t, "run client")

	// Check for errors during replay
	if len(client_err.savedOutput) > 0 {
		t.Fatalf("Delve client errored: %s", client_err.savedOutput)
	}
	if len(server_err.savedOutput) > 0 {
		t.Fatalf("Delve server errored while client running: %s", server_err.savedOutput)
	}

	checkWatchpoints(t, client_out.savedOutput, lines, watchexprs)
}

func parseWatchAddr(t *testing.T, stdout []byte, log_msg string) *uint64 {
	if idx := strings.Index(string(stdout), log_msg); idx != -1 {
		var watchaddr uint64
		line := string(stdout)[idx+len(log_msg):]
		if _, err := fmt.Sscanf(line, "%x\n", &watchaddr); err != nil {
			t.Fatalf("Wrong log format")
		}
		return &watchaddr
	}
	return nil
}

func checkWatchpoints(t *testing.T, stdout []byte, lines []int, watchexprs []string) {
	create_nonpending_fmt := "CreateWatchpoint: line %v, watchexpr %v, watchaddr 0x"
	create_hw_pending_fmt := "CreateWatchpoint (was hardware-pending): line %v, watchaddr 0x%x\n"
	record_hw_pending_fmt := "Hardware-pending createWatchpoint: line %v, watchexpr %v, watchaddr 0x"

	// Check expected wps were created, and mem-config map was updated
	for i, line := range lines {
		var create string
		var watchaddr uint64
		record_hw_pending := fmt.Sprintf(record_hw_pending_fmt, line, watchexprs[i])
		pending_watchaddr := parseWatchAddr(t, stdout, record_hw_pending)
		if pending_watchaddr != nil {
			// Expect to see this watchexpr created with addr, not expr
			create = fmt.Sprintf(create_hw_pending_fmt, line, *pending_watchaddr)
			watchaddr = *pending_watchaddr
		} else {
			create = fmt.Sprintf(create_nonpending_fmt, line, watchexprs[i])
			nonpending_watchaddr := parseWatchAddr(t, stdout, create)
			if nonpending_watchaddr == nil {
				t.Fatalf("Client did not log watchaddr for non-pending watchpoint: %v", create)
			}
			watchaddr = *nonpending_watchaddr
		}

		// wp
		if !strings.Contains(string(stdout), create) {
			t.Fatalf("Client did not log creation of expected watchpoint: %v", create)
		}

		// mem-config map
		mem_param_fmt := "\tMemory-parameter map: 0x%x => {params:map[{param:%v flow:1}:{}]}\n"
		mem_param := fmt.Sprintf(mem_param_fmt, watchaddr, watchexprs[0])
		if !strings.Contains(string(stdout), mem_param) {
			t.Fatalf("Client did not log expected update of memory-parameter map: %v", mem_param)
		}
	}

	// Check no unexpected wps were created
	n_created_wp := strings.Count(string(stdout), "CreateWatchpoint")
	if n_created_wp != len(lines) {
		t.Fatalf("Client created %v watchpoints, expected %v", n_created_wp, len(lines))
	}
}
