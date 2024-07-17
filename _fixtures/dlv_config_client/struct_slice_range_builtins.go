package main

import "fmt"

type Conf struct {
	search []string
}

func main() {
	conf := &Conf{search: []string{"hi", "hello"}} // conf.search is initially tainted
	names := make([]string, 0, len(conf.search))
	// 1st iter: hit for conf.search x 2 => propagate to suffix
	// 2nd iter: hit for suffix => nowhere to propagate
	for _, suffix := range conf.search {
		// runtime hit (of suffix[0]) => propagate to names (once exit range)
		names = append(names, "localhost"+suffix)
	}
	fmt.Println(names)          // hit for names
	if conf.search[0] == "hi" { // hit for conf.search x 6, suffix[0] (reusing mem)
		fmt.Println("yep")
	}
}
