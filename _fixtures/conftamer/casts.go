package main

import (
	"fmt"
	"runtime"
	_ "syscall"
)

type MyType int

func f(x_callee int) int {
	fmt.Println(x_callee)
	return 1
}

func main() {
	x := 1 // initially tainted
	runtime.KeepAlive(x)
	y := int(x) // cast dlv supports evaluating
	fmt.Printf("using y %v\n", y)
	z := MyType(x) // cast dlv doesn't support
	fmt.Println(z)

	z2 := int(f(x)) // casted fn call => ignore cast, propagate into fn
	_ = z2
}
