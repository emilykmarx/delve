package main

import (
	"fmt"
	_ "syscall"
)

type Conf struct {
	search []string // slice
}

func struct_slice_append() []string {
	conf := &Conf{search: []string{"hi", "hello"}} // conf.search is initially tainted
	names := make([]string, 0, len(conf.search))
	// Suffix reuses conf.search's backing arrays
	for i, suffix := range conf.search {
		fmt.Printf("iter %v\n", i)
		// runtime hits (of suffix backing array) => propagate to names
		names = append(names, "localhost"+suffix) // slice w/ a new backing array
	}

	fmt.Println()
	return names
}

func main() {
	names_caller := struct_slice_append()       // reuses names backing array
	names2 := make([]string, len(names_caller)) // reuses names backing array
	copy(names2[:], names_caller)               // runtime hit => ignore
	fmt.Println()
}
