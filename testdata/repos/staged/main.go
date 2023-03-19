package main

import (
	"fmt"
	"os"
)

func main() {

	var a = "initial"
	fmt.Println(a)

	var b, c int = 1, 2
	fmt.Println(b, c)

	var d = true
	fmt.Println(d)

	var e int
	fmt.Println(e)

	// load secret via env
	awsToken := os.Getenv("AWS_TOKEN")

	f := "apple"
	fmt.Println(f)
}
