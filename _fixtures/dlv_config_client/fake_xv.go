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
