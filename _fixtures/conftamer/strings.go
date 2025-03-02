package main

import (
	"fmt"
	_ "syscall"
)

func f() string {
	return "more"
}

func main() {
	s := "hi" // s is initially tainted
	// Runtime hit (of s[0]) => propagate to s2
	s2 := f() + s
	fmt.Printf("%v\n", s2)
	// Index s => propagate to i
	i := s[0]
	fmt.Printf("%v\n", i)
}
