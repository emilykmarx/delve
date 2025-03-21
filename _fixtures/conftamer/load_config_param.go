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
	bytes, err := os.ReadFile(config_file) // bp hit for read file => watch bytes (but param not filled in yet)
	// bytes is alias for buf passed to syscall
	if err != nil {
		log.Panicf("ReadFile: %v", err)
	}
	params := "param1\nparam2"
	bytes2 := make([]byte, len(params))
	copy(bytes2, bytes) // wp hit for bytes => taint corresp offsets of bytes2 with param1 or param2
	param1_var := make([]byte, len("param1"))
	copy(param1_var, bytes2) // wp hit for bytes2 => taint param1_var with "param1"
	fmt.Println(string(param1_var))
}
