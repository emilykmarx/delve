package main

import (
	"fmt"
	"runtime"
	"sync"
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

func ret_untainted(tainted_param int) int {
	// line w/o stmt
	runtime.KeepAlive(tainted_param)
	fmt.Printf("Reading tainted_param %v\n", tainted_param)
	return 2
}

func ret_tainted(tainted_param_2 int) int {
	runtime.KeepAlive(tainted_param_2)
	fmt.Printf("Reading tainted_param_2 %v\n", tainted_param_2)
	return tainted_param_2
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

// Expect 6 hits
func callAndAssign() {
	var stack int // Stack is initially tainted
	// Hit for stack x 2, tainted_param_2 x 2
	runtime.KeepAlive(stack)
	a := ret_tainted(stack) + stack // Call+assign, hit in both => propagate to tainted_param and a
	// Hit for a x 2
	fmt.Printf("Using a%v\n", a)
	runtime.KeepAlive(a)
}

// TODO add test for stack resize
// TODO automate this test better - maybe don't rely on hitting wp? Also check server output for errors
// Add new tests in diff functions to maintain asm for old ones
// Expect 11 hits
func main() {
	multiRound()
	return

	var stack int // Stack is initially tainted
	var spacer int
	// Hit for stack
	stack = 1                // Write stack
	runtime.KeepAlive(stack) // Not a read (copies from rax to its own stack location)
	// Hit for stack
	spacer = stack            // Assign => propagate to spacer
	runtime.KeepAlive(spacer) // Need for param passing to read spacer
	// Hit for spacer, tainted_param
	y := ret_untainted(spacer+1) + 3 // Call+assign, hit in call, untainted ret => propagate to tainted_param
	runtime.KeepAlive(y)
	// Hit for spacer, tainted_param_2 x 2
	y = ret_tainted(spacer+1) + 3 // Call+assign, hit in call, tainted ret => propagate to tainted_param and y
	// Hit for y
	fmt.Printf("Using y%v\n", y)
	// Hit for spacer
	z := ret_untainted(3) + spacer // Call+assign, hit in assign rhs => propagate to z
	// Hit for z
	fmt.Printf("Using z%v\n", z)
	// Hit for z
	runtime.KeepAlive(z)
}
