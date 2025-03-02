package main

import (
	"fmt"
	_ "syscall"
)

type Name struct {
	Data   [255]byte
	Length uint8
}

func NewName_(name_callee string) (Name, error) {
	n := Name{Length: uint8(len(name_callee))}
	copy(n.Data[:], name_callee) // propagate to n.Data
	return n, nil                // runtime hit => propagate to n_caller.Data
}

func main() {
	name := "hi" // initially tainted
	n_caller, _ := NewName_(name)
	fmt.Printf("%v\n", n_caller)
}
