package main

import (
	"fmt"
	_ "syscall"
)

func main() {
	arr := [2]int{0, 1} // initially tainted
	s := arr[1:]        // propagate to slice (s)
	fmt.Printf("%v\n", s)
}
