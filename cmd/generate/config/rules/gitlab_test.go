package rules

import (
	"pgregory.net/rapid"
	"testing"
)

func Test_GitlabPat(t *testing.T) {
	r := *GitlabPat()
	genSecret := rapid.StringMatching(`glpat-[0-9a-zA-Z\-\_]{20}`)

	t.Run("true positives", rapid.MakeCheck(func(t *rapid.T) {
		secret := genSecret.Draw(t, "")
		ValidateTruePositive(t, r, secret)
	}))

	t.Run("false positives", func(t *testing.T) {
		fps := []string{
			`glpat-xxxxxxxxxxxxxxxxxxxx`, // low entropy
		}
		for _, fp := range fps {
			ValidateFalsePositive(t, r, fp)
		}
	})
}

func Test_GitlabPipelineTriggerToken(t *testing.T) {
	r := *GitlabPipelineTriggerToken()
	genSecret := rapid.StringMatching(`glptt-[0-9a-f]{40}`)

	t.Run("true positives", rapid.MakeCheck(func(t *rapid.T) {
		secret := genSecret.Draw(t, "")
		ValidateTruePositive(t, r, secret)
	}))

	t.Run("false positives", func(t *testing.T) {
		fps := []string{
			`glptt-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`, // low entropy
		}
		for _, fp := range fps {
			ValidateFalsePositive(t, r, fp)
		}
	})
}

func Test_GitlabRunnerRegistrationToken(t *testing.T) {
	r := *GitlabRunnerRegistrationToken()
	genSecret := rapid.StringMatching(`GR1348941[\w-]{20}`)

	t.Run("true positives", rapid.MakeCheck(func(t *rapid.T) {
		secret := genSecret.Draw(t, "")
		ValidateTruePositive(t, r, secret)
	}))

	t.Run("false positives", func(t *testing.T) {
		fps := []string{
			`GR1348941xxxxxxxxxxxxxxxxxxxx`, // low entropy
		}
		for _, fp := range fps {
			ValidateFalsePositive(t, r, fp)
		}
	})
}
