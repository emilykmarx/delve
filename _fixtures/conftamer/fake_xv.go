package main

import "runtime"

func sortByRFC6724withSrcs(addrs int) {
	if addrs == 0 { // addrs gets an addr only after executing first instr in line
		panic("internal error")
	}
}

func main() {
	a := 5
	runtime.KeepAlive(a)
	sortByRFC6724withSrcs(a)
}

/*
another repro:
	X int
}

func (recvr_callee Recvr) f() {
	x_callee := recvr_callee.X // propagate to x_callee
	fmt.Printf("using x_callee %v\n", x_callee)
}
recvr_callee is fake at first line

But if it's:
func (recvr_callee Recvr) f() {
	fmt.Printf("using recvr %v\n", recvr_callee)
}

recvr_callee is not fake at first line

Also:
func (recvr_callee Recvr) f() {
	y := 1
	x_callee := recvr_callee.X // propagate to x_callee
	fmt.Printf("using x_callee %v\n", x_callee)
	fmt.Printf("using x_callee %v\n", y)
}

at first line, recvr_callee.X is not fake but still has beef addr
*/
