package main

import (
	"fmt"
	"log"
	_ "net/http/pprof"
	"os"
)

func main() {
	config_file := os.Getenv("config")
	fmt.Printf("config file in target: %v\n", config_file)
	if config_file == "" {
		log.Panicf("config file not set")
	}
	bytes, err := os.ReadFile(config_file)
	// bytes is alias for buf passed to syscall
	if err != nil {
		log.Panicf("ReadFile: %v", err)
	}
	param1_var := make([]byte, len("param1"))
	copy(param1_var, bytes) // wp hit for read buf => taint param1 with text in that portion of read buf
	fmt.Println(string(param1_var))
}
