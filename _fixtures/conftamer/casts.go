package main

import (
	_ "syscall"
)

func main() {
	x := "hi"      // initially tainted
	y := []byte(x) // aliased primitive type, invalid regex
	_ = y
}
