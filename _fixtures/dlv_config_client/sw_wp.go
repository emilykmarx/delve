package main

import (
	"fmt"
	_ "syscall"
)

func main() {
	x := 1 // initially tainted => set sw wp (i.e. mprotect this page)
	// should segfault from accessing the page before exiting
	fmt.Println(x)
}
