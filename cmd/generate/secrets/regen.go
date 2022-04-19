// Package reggen generates text based on regex definitions
// This is a slightly altered version of https://github.com/lucasjones/reggen
package secrets

import (
	"github.com/lucasjones/reggen"
)

func NewSecret(regex string) string {
	g, err := reggen.NewGenerator(regex)
	if err != nil {
		panic(err)
	}
	return g.Generate(1)
}
