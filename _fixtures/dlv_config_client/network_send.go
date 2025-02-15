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

	config := []byte("config") // config[1] initially tainted

	nd := net.Dialer{
		//Timeout: 5 * time.Second, # makes manual debugging annoying, but likely want for automated test
	}
	conn, err := nd.Dial("tcp", endpoint)
	if err != nil {
		log.Panicf("Dial: %v", err)
	}
	_, err = conn.Write(config)
	if err != nil {
		log.Panicf("Write: %v", err)
	}
	// behavior map should record message offset 1 is tainted by config[1]
	// (when dial tcp, msgs are raw tcp not http)
	fmt.Println("target exit")
}
