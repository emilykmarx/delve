package main

import (
	"fmt"
	_ "syscall"
)

func main() {
	x := 1 // initially tainted => set sw wp (i.e. mprotect this page)
	// should hit once
	fmt.Println(x)
}
