package api

import "fmt"

func PrintHello() {
	aws_token := "AKIALALEMEL33243OLIA"  // fingerprint of that secret is added to .gitleaksignore
	aws_token2 := "AKIALALEMEL33243OLIA" // this one is not
	fmt.Println(aws_token)
	fmt.Println(aws_token2)
}
