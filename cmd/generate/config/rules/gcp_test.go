package rules

import (
	"pgregory.net/rapid"
	"testing"
)

func Test_GCPAPIKey(t *testing.T) {
	r := *GCPAPIKey()
	genSecret := rapid.StringMatching(`AIza[\w-]{35}`)

	t.Run("true positives", rapid.MakeCheck(func(t *rapid.T) {
		secret := genSecret.Draw(t, "")
		ValidateTruePositive(t, r, secret)
	}))

	t.Run("false positives", func(t *testing.T) {
		fps := []string{
			`AIzaxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`, // low entropy
		}
		for _, fp := range fps {
			ValidateFalsePositive(t, r, fp)
		}
	})
}
