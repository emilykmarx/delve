package main

import (
	"fmt"
	"runtime"
	_ "syscall"
)

var (
	G = 1
)

func f() {
	y := 2
	runtime.KeepAlive(G)
	if G == 1 {
		y = G
	}
	_ = y
	fmt.Println(y)
}

func main() {
	x := 1
	fmt.Println(x)
	//for i := 0; i < 100; i++ {
	f()
	//}
}
