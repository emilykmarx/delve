package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"time"
)

func main() {
	endpoint := "localhost:6060"
	go func() {
		log.Println(http.ListenAndServe(endpoint, nil))
	}()

	// wait for server to start (so Dial will succeed)
	time.Sleep(1 * time.Second)

	config := []byte("config") // config initially tainted

	nd := net.Dialer{
		//Timeout: 5 * time.Second, # makes manual debugging annoying, but likely want for automated test
	}
	conn, err := nd.Dial("tcp", endpoint)
	if err != nil {
		log.Panicf("Dial: %v", err)
	}
	_, err = conn.Write(config[1:]) // Case 2: beginning of watch region < beginning of msg (XXX add test for opposite)
	if err != nil {
		log.Panicf("Write: %v", err)
	}
	// behavior map should record message offsets 0-4 are tainted by config
	// (when dial tcp, msgs are raw tcp not http)
	fmt.Println("target exit")
}
