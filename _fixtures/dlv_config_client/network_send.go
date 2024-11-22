package main

import (
	"fmt"
	"os"
	_ "syscall"
)

func main() {
	buf := []byte("hi") // initially tainted
	if err := os.WriteFile("/tmp/aaah", buf, 0644); err != nil {
		fmt.Printf("err writing file: %v\n", err.Error())
	}
}
