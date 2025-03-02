package main

import (
	"fmt"
	"runtime"
	"sync"
	_ "syscall"
)

func main() {
	var wg sync.WaitGroup

	fqdn := "fqdn" // fqdn is initially tainted
	var queryFn func(fqdn string)

	queryFn = func(fqdn string) {
		wg.Add(1)
		fmt.Printf("Using fdqn: %v\n", fqdn)
		go func() {
			defer wg.Done()

			fmt.Printf("Using fdqn in goroutine: %v\n", fqdn)
		}()
	}

	runtime.KeepAlive(fqdn)
	queryFn(fqdn) // hit for fqdn => propagate to callee
	wg.Wait()
}
