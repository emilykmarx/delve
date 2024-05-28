package main

import (
	"fmt"
	"runtime"
)

func ret_untainted(tainted_param int) int {
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

func strings() {
	// Swap out other s2 line and also run that
	s := "hi"
	s2 := f() + s // regular hit (of s) => propagate to s
	//	s2 := "hello" + s      // runtime hit (of s[0]) => propagate to s2
	fmt.Printf("%v\n", s2) // runtime hit => no propagate (args to print.go not tainted)
}

func composites() {
	conf := &Conf{search: []string{"hi", "hello"}} // conf.search[0] is initially tainted
	names := make([]string, 0, len(conf.search))
	for _, suffix := range conf.search { // hit for conf.search => propagate to suffix
		names = append(names, "localhost"+suffix) // runtime hit (of suffix[0]) => propagate to names
	}
	fmt.Println(names)
	// TODO also test hits for arr[i], just arr (hopefully they hit for the arr ptr watch, unlike strings)
}

// TODO add test for stack resize
// TODO automate this test better - maybe don't rely on hitting wp?
// Adding new tests in diff functions may maintain asm for old ones?
// Expect 11 hits
func main() {
	composites()
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
