package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func JWT() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "JSON Web Token",
		RuleID:      "jwt",
		Regex:       generateUniqueTokenRegex(`ey[0-9a-z]{30,34}\.ey[0-9a-z-\/_]{30,500}\.[0-9a-zA-Z-\/_]{10,200}={0,2}`),
		Keywords:    []string{"ey"},
	}

	// validate
	tps := []string{`eyJhbGciOieeeiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwic3ViZSI6IjEyMzQ1Njc4OTAiLCJuYW1lZWEiOiJKb2huIERvZSIsInN1ZmV3YWZiIjoiMTIzNDU2Nzg5MCIsIm5hbWVmZWF3ZnciOiJKb2huIERvZSIsIm5hbWVhZmV3ZmEiOiJKb2huIERvZSIsInN1ZndhZndlYWIiOiIxMjM0NTY3ODkwIiwibmFtZWZ3YWYiOiJKb2huIERvZSIsInN1YmZ3YWYiOiIxMjM0NTY3ODkwIiwibmFtZndhZSI6IkpvaG4gRG9lIiwiaWZ3YWZhYXQiOjE1MTYyMzkwMjJ9.a_5icKBDo-8EjUlrfvz2k2k-FYaindQ0DEYNrlsnRG0==`, // gitleaks:allow
		`JWT := eyJhbGciOieeeiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwic3ViZSI6IjEyMzQ1Njc4OTAiLCJuYW1lZWEiOiJKb2huIERvZSIsInN1ZmV3YWZiIjoiMTIzNDU2Nzg5MCIsIm5hbWVmZWF3ZnciOiJKb2huIERvZSIsIm5hbWVhZmV3ZmEiOiJKb2huIERvZSIsInN1ZndhZndlYWIiOiIxMjM0NTY3ODkwIiwibmFtZWZ3YWYiOiJKb2huIERvZSIsInN1YmZ3YWYiOiIxMjM0NTY3ODkwIiwibmFtZndhZSI6IkpvaG4gRG9lIiwiaWZ3YWZhYXQiOjE1MTYyMzkwMjJ9.a_5icKBDo-8EjUlrfvz2k2k-FYaindQ0DEYNrlsnRG0`, // gitleaks:allow
	}
	return validate(r, tps, nil)
}
