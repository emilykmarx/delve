package main_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	protest "github.com/go-delve/delve/pkg/proc/test"
)

func multiRound() {
	// vars[0] initially tainted, bp_addr = range stmt
	vars := []int{0, 1, 2, 3, 4, 5}
	for i := range vars {
		if i > 0 {
			// hit for vars[i-1] => prop to vars[i]
			// Round 1: set wp for vars[1,2,3], 4 and 5 are pending
			// Round 2: set wp for vars[4,5]
			vars[i] = vars[i-1]
			// put off properly finding when var is in scope (should likely be next TODO...)
			fmt.Println()
		}
	}
}

type Conf struct {
	search []string
}

func f() string {
	return "more"
}

func funcLitGoroutine() {
	var wg sync.WaitGroup

	fqdn := "fqdn" // fqdn is initially tainted
	var queryFn func(fqdn string)

	queryFn = func(fqdn string) {
		wg.Add(1)
		fmt.Printf("Using fdqn: %v\n", fqdn) // hit for fqdn => ignore from there (prop w/in Printf -- should maybe ignore...)
		go func() {
			defer wg.Done()

			fmt.Printf("Using fdqn in goroutine: %v\n", fqdn) // hit for fqdn => ignore from there (prop w/in Printf -- should maybe ignore...)
		}()
	}

	runtime.KeepAlive(fqdn)
	queryFn(fqdn) // hit for fqdn => propagate to arg
	wg.Wait()
}

/*
// Expect 4 hits, failure to set last wp
func strings() {
	s := "hi" // s is initially tainted
	// regular hit (of s) => propagate to s2.
	// also runtime hit (of s[0]) => propagate to s2
	s2 := f() + s
	// regular hit (of s2) => no defn for Printf
	// also runtime hit (of s2[0]) => try propagate to print.go buffer, but too large and out of hw wp
	fmt.Printf("%v\n", s2)
}
*/

// Expect 12 hits
func structSliceRangeBuiltins() {
	// TODO once this passes: update comments
	conf := &Conf{search: []string{"hi", "hello"}} // conf.search is initially tainted
	names := make([]string, 0, len(conf.search))
	// 1st iter: hit for conf.search x 2 => propagate to suffix
	// 2nd iter: hit for suffix => nowhere to propagate
	for _, suffix := range conf.search {
		// runtime hit (of suffix[0]) => propagate to names (once exit range)
		names = append(names, "localhost"+suffix)
	}
	fmt.Println(names)          // hit for names
	if conf.search[0] == "hi" { // hit for conf.search x 6, suffix[0] (reusing mem)
		fmt.Println("yep")
	}
}

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
	ctx, cancel = context.WithTimeout(context.Background(), 3*record_time)
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
	server.Process.Kill()
	server.Wait()
}

// TODO add test for stack resize
// TODO automate this test better - maybe don't rely on hitting wp? Also check server output for errors
// Add new tests in diff functions to maintain asm for old ones
func main() {
	multiRound()
	return

}
