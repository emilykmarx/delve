package main

import (
	"encoding/json"
	"fmt"
	"log"
	_ "syscall"
)

type Config struct {
	AppsRaw string `json:"apps,omitempty" caddy:"namespace="`
}

func main() {
	appsRaw := "http"
	c := Config{AppsRaw: appsRaw} // initially tainted: c.AppsRaw ("http", 4B)
	marshaled, err := json.Marshal(&c)
	if err != nil {
		log.Panicf("marshal: %v", err)
	}
	fmt.Printf("marshaled: %+v\n", string(marshaled)) // {"apps":"http"} (len 15)
	// http part should be tainted (offsets 9:12 inclusive)
	// wp is set via `buf` at encode.go:169
}
