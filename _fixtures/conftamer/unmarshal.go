package main

import (
	"fmt"
	"log"
	"reflect"
	_ "syscall"
	"unsafe"

	"gopkg.in/yaml.v2"
)

type Config struct {
	A []string
}

func main() {
	data := []byte("a: [\"hi\"]")
	var c Config
	err := yaml.Unmarshal(data, &c)
	if err != nil {
		log.Panicf("unmarshal: %v", err)
	}
	fmt.Printf("unmarshaled: %+v\n", c)
	fmt.Println(c.A[0][0])
	fmt.Println(c.A[0][1])
	/*
		This works to get addr of underlying data but wp hits in StringToBytes and client doesn't handle it well, so never prints addr
		And can't print addr before unmarshal, bc underlying data not allocated yet
			p := StringToBytes(c.A[0])
			// Should match the watchpoint on n.value
			fmt.Printf("Addr of output struct's underlying data: %p\n", &p[0])
	*/
}

func StringToBytes(s string) []byte {
	const max = 0x7fff0000
	if len(s) > max {
		panic("string too long")
	}
	return (*[max]byte)(unsafe.Pointer((*reflect.StringHeader)(unsafe.Pointer(&s)).Data))[:len(s):len(s)]
}
