package main

import (
	"fmt"
	"runtime"
)

// (CallAssign1 also has a receiver-related test: tainting non-receiver args to a method)
type Recvr struct {
	X int
}

func (recvr_callee Recvr) f() {
	fmt.Printf("using recvr %v\n", recvr_callee) // needed so recvr_callee.X gets an addr
	x_callee := recvr_callee.X                   // propagate to x_callee
	fmt.Printf("using x_callee %v\n", x_callee)
}

// Propagate to non-pointer receiver (callee gets a copy)
func main() {
	x := 1 // x initially tainted
	runtime.KeepAlive(x)
	recvr := Recvr{X: x} // propagate to recvr.X
	runtime.KeepAlive(recvr)
	recvr.f() // propagate to function's copy of recvr.X
}
