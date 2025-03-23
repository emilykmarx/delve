package main

import (
	"fmt"
	_ "syscall"
)

func main() {
	config := "config" // config[0] initially tainted
	maybe_tainted := "maybe"
	maybe_tainted_2 := "maybe"
	maybe_tainted_3 := "maybe"
	maybe_tainted_4 := "maybe"
	maybe_tainted_5 := "maybe"
	var regular byte

	if config[0] == 'c' { // hit for config in if/else condition, where take if branch
		maybe_tainted = "yes" // propagate to maybe_tainted, via CF
		maybe_tainted_2 = "2" // propagate to maybe_tainted_2, via CF
		// regular wp hit in body => propagate to regular for config[0] via both DF and CF
		// (need to resolve in graph-making)
		regular = config[0]
		fmt.Println() // line to set wp on
	} else {
		fmt.Println()
	}

	if config[0] == 'd' { // hit for config in if/else condition, where take else branch
		fmt.Println()
	} else {
		maybe_tainted_3 = "3" // propagate to maybe_tainted, via CF
		fmt.Println()
	}

	if config[0] == 'c' { // hit for config in if condition
		maybe_tainted_4 = "4" // propagate to maybe_tainted_4, via CF
	}

	if config[0] == 'd' { // hit for config in if/else if/else condition, where take elseif branch
		fmt.Println()
	} else if config[1] == 'o' { // not a hit
		maybe_tainted_5 = "ohyes" // propagate to maybe_tainted_5, via CF
		fmt.Println()
	} else {
		fmt.Println()
	}

	i := maybe_tainted[0] // regular hit for maybe_tainted => propagate to i, via CF
	j := config[0]        // regular hit for config => propagate to j, via DF
	k := 2                // no hit (check we've stopped tainting everything)
	fmt.Println(i)
	fmt.Println(j)
	fmt.Println(k)

	fmt.Println(maybe_tainted)
	fmt.Println(maybe_tainted_2)
	fmt.Println(maybe_tainted_3)
	fmt.Println(maybe_tainted_4)
	fmt.Println(maybe_tainted_5)
	fmt.Println(regular)
}
