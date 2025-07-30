package main

import (
	"fmt"
	"log"
	_ "syscall"

	"gopkg.in/yaml.v2"
)

type Config struct {
	A []string
}

func main() {
	data := []byte("a: [\"hi\"]")
	var c Config // should end up tainted
	err := yaml.Unmarshal(data, &c)
	if err != nil {
		log.Panicf("unmarshal: %v", err)
	}
	fmt.Printf("unmarshaled: %+v\n", c)
	tainted1 := c.A[0][0] // copy vals so can check watchpoint by name (wps are set via aliasing)
	tainted2 := c.A[0][1]
	_ = tainted1
	_ = tainted2
}
