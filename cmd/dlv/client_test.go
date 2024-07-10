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

func TestCallAndAssign(t *testing.T) {
	run(t, "call_assign.go", 37, "stack")
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

func run(t *testing.T, testfile string, initial_bp_line int, initial_watchexpr string) {
	// Start dlv server, wait for it to finish recording
	var server_out saveOutput
	var server_err saveOutput

	listenAddr := "localhost:4040"
	fixturePath := filepath.Join(protest.FindFixturesDir(), "dlv_config_client", testfile)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := exec.CommandContext(ctx, getDlvBin(t), "debug", "--headless", "--backend=rr",
		"--api-version=2", "--accept-multiclient", "--listen", listenAddr, fixturePath)

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

	server.Stdout = &server_out
	server.Stderr = &server_err

	assertNoError(server.Start(), t, "start headless instance")
	record_time := waitForReplay(t, &server_out, &server_err)

	// Run dlv client until exit or timeout (assume replay time <= 3x record time)
	client_timeout := 3 * record_time
	t.Logf("Starting client with timeout %v\n", client_timeout)
	ctx, cancel = context.WithTimeout(context.Background(), client_timeout)
	defer cancel()
	client := exec.CommandContext(ctx, getClientBin(t),
		"-initial_bp_file="+fixturePath, fmt.Sprintf("-initial_bp_line=%v", initial_bp_line),
		"-initial_watchexpr="+initial_watchexpr)
	out, err := client.CombinedOutput()
	fmt.Printf("Client output: %s\n", string(out))
	assertNoError(err, t, "client output")

	// Final server error check (TODO test this)
	if len(server_err.savedOutput) > 0 {
		t.Fatalf("Delve server errored while client running")
	}
}
