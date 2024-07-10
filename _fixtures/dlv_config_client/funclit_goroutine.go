package main

import (
	"fmt"
	"runtime"
	"sync"
)

func main() {
	var wg sync.WaitGroup

	fqdn := "fqdn" // fqdn is initially tainted
	var queryFn func(fqdn string)

	queryFn = func(fqdn string) {
		wg.Add(1)
		fmt.Printf("Using fdqn: %v\n", fqdn) // hit for fqdn => ignore from there (prop w/in Printf -- should maybe ignore...)
		go func() {
			defer wg.Done()

			fmt.Printf("Using fdqn in goroutine: %v\n", fqdn) // hit for fqdn => ignore from there (prop w/in Printf -- should maybe ignore...)
		}()
	}

	runtime.KeepAlive(fqdn)
	queryFn(fqdn) // hit for fqdn => propagate to arg
	wg.Wait()
}
