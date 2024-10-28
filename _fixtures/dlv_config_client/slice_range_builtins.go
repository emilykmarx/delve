package main

import (
	"fmt"
	_ "syscall"
)

type Conf struct {
	search []string
}

func struct_slice_append() []string {
	conf := &Conf{search: []string{"hi", "hello"}} // conf.search is initially tainted
	names := make([]string, 0, len(conf.search))
	// 1st iter: hit for conf.search x 2 => propagate to suffix
	// 2nd iter: hit for suffix => nowhere to propagate
	for _, suffix := range conf.search {
		// runtime hit (of suffix[0]) => propagate to names (once exit range)
		names = append(names, "localhost"+suffix)
	}

	fmt.Println()
	return names
}

func main() {
	names_caller := struct_slice_append() // propagate to caller copy of names
	names2 := make([]string, len(names_caller))
	copy(names2[:], names_caller) // propagate to names2
	fmt.Println()
}
