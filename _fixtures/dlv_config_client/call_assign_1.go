package main

import (
	"fmt"
	"runtime"
	_ "syscall"
)

type Recvr struct {
	X int
}

func (Recvr) ret_untainted(tainted_param int) int {
	// line w/o stmt
	runtime.KeepAlive(tainted_param)
	fmt.Printf("Reading tainted_param %v\n", tainted_param)
	return 2
}

func (*Recvr) ret_tainted(tainted_param_2 int) int {
	runtime.KeepAlive(tainted_param_2)
	fmt.Printf("Reading tainted_param_2 %v\n", tainted_param_2)
	return tainted_param_2
}

func main() {
	recvr := Recvr{X: 2}
	var stack int // Stack is initially tainted
	var spacer int
	// Hit for stack
	stack = 1                // Write stack
	runtime.KeepAlive(stack) // Not a read (copies from rax to its own stack location)
	// Hit for stack
	spacer = stack            // Assign => propagate to spacer
	runtime.KeepAlive(spacer) // Need for param passing to read spacer
	// Hit for spacer, tainted_param
	y := recvr.ret_untainted(spacer+1) + 3 // Call+assign, hit in call, untainted ret => propagate to tainted_param
	runtime.KeepAlive(y)
	// Hit for spacer, tainted_param_2 x 2
	y = recvr.ret_tainted(spacer+1) + 3 // Call+assign, hit in call, tainted ret => propagate to tainted_param_2 and y
	// Hit for y
	fmt.Printf("Using y%v\n", y)
	// Hit for spacer
	z := recvr.ret_untainted(3) + spacer // Call+assign, hit in assign rhs => propagate to z
	// Hit for z
	fmt.Printf("Using z%v\n", z)
	// Hit for z
	runtime.KeepAlive(z)
}
