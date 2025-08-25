package main

import (
	"encoding/json"
	"fmt"
	"log"
	_ "syscall"
)

type Config struct {
	AppsRaw [5]byte `json:"apps,omitempty" caddy:"namespace="`
}

func main() {
	appsRaw := "http"
	c := Config{} // initially tainted: c.AppsRaw ("http", 4B)
	c.AppsRaw[len(c.AppsRaw)-1] = 0x41
	copy(c.AppsRaw[:], appsRaw)
	marshaled, err := json.Marshal(&c)
	if err != nil {
		log.Panicf("marshal: %v", err)
	}
	fmt.Printf("marshaled: %+v\n", string(marshaled)) // {"apps":"httpA"} (len 16)
	// http part should be tainted (offsets 9:12 inclusive)
	// wp is set via `buf` at encode.go:169
}
