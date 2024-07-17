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
	lines := []int{13, 14}
	watchexprs := []string{"s", "s2"}
	run(t, "strings.go", lines, watchexprs)
}

func TestStructSliceRangeBuiltins(t *testing.T) {
	lines := []int{11, 16, 18}
	watchexprs := []string{"conf.search", "suffix", "names"}
	run(t, "struct_slice_range_builtins.go", lines, watchexprs)
}

func TestFuncLitGoRoutine(t *testing.T) {
	lines := []int{13, 16}
	watchexprs := []string{"fqdn", "fqdn"}
	run(t, "funclit_goroutine.go", lines, watchexprs)
}

func waitForReplay(t *testing.T, stdout *saveOutput, stderr *saveOutput) time.Duration {
	start := time.Now()
	// Wait for output so can check error
	for ; len(stdout.savedOutput) == 0; time.Sleep(time.Second) {
	}
	if !strings.HasPrefix(string(stdout.savedOutput), "API server listening at:") {
		t.Fatalf("Delve server failed to start listening")
	}

	for {
		if len(stderr.savedOutput) > 0 {
			t.Fatalf("Delve server errored while starting up (perf counters in use?)")
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
			return time.Since(start)
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
	server := exec.CommandContext(ctx, getDlvBin(t), "debug", "--headless", "--backend=rr",
		"--api-version=2", "--accept-multiclient", "--listen", listenAddr, fixturePath)

	var server_out saveOutput
	var server_err saveOutput
	server.Stdout = &server_out
	server.Stderr = &server_err

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

	assertNoError(server.Start(), t, "start headless instance")
	record_time := waitForReplay(t, &server_out, &server_err)

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

func checkWatchpoints(t *testing.T, stdout []byte, lines []int, watchexprs []string) {
	log_msg_format := "CreateWatchpoint: line %v, watchexpr %v\n"
	for i, line := range lines {
		log_msg := fmt.Sprintf(log_msg_format, line, watchexprs[i])
		if !strings.Contains(string(stdout), log_msg) {
			t.Fatalf("Client did not log creation of expected watchpoint: %v", log_msg)
		}
	}

	n_created_wp := strings.Count(string(stdout), "CreateWatchpoint: ")
	if n_created_wp != len(lines) {
		t.Fatalf("Client created %v watchpoints, expected %v", n_created_wp, len(lines))
	}
}
