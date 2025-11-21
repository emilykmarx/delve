package main

import "fmt"

type xType struct{}
type yType struct{}
type zType struct{}

func (xType) doSomething() { fmt.Println("xType does something"); }
func (yType) doSomething() { fmt.Println("yType does something"); }
func (zType) doSomething() { fmt.Println("zType does something"); }

func main() {
	xType{}.doSomething()
	yType{}.doSomething()
	zType{}.doSomething()
	fmt.Println("Finished");
}
