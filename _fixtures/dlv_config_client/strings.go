package main

import "fmt"

func f() string {
	return "more"
}

// Expect 4 hits, failure to set last wp
func main() {
	s := "hi" // s is initially tainted
	// regular hit (of s) => propagate to s2.
	// also runtime hit (of s[0]) => propagate to s2
	s2 := f() + s
	// regular hit (of s2) => no defn for Printf
	// also runtime hit (of s2[0]) => try propagate to print.go buffer, but too large and out of hw wp
	fmt.Printf("%v\n", s2)
}
