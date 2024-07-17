package main

import "fmt"

func f() string {
	return "more"
}

func main() {
	s := "hi" // s is initially tainted
	// regular hit (of s) => propagate to s2.
	// also runtime hit (of s[0]) => propagate to s2
	s2 := f() + s
	fmt.Printf("%v\n", s2)
}
