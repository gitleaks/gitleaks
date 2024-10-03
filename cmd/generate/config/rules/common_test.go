package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"pgregory.net/rapid"
	"strings"
	"testing"
)

func ValidateTruePositive(t *rapid.T, r config.Rule, truePositive string) {
	t.Helper()

	// normalize keywords like in the config package
	var keywords []string
	for _, k := range r.Keywords {
		keywords = append(keywords, strings.ToLower(k))
	}
	r.Keywords = keywords

	rules := make(map[string]config.Rule)
	rules[r.RuleID] = r
	d := detect.NewDetector(config.Config{
		Rules:    rules,
		Keywords: keywords,
	})

	entropy := detect.ShannonEntropy(truePositive)
	if len(d.DetectString(truePositive)) == 0 {
		// Skip secret, it doesn't have enough entropy.
		if r.Entropy > 0 && entropy < r.Entropy {
			t.Logf("Skipping generate secret, insufficient entropy: '%s'\n", truePositive)
			return
		}
		t.Fatalf("True positive was not detected by regex.")
	} else if r.Entropy > 0 && entropy < r.Entropy {
		t.Fatalf("True positive was detected with insufficient entropy (%f < %f)", entropy, r.Entropy)
	}
}

func ValidateFalsePositive(t *testing.T, r config.Rule, falsePositive string) {
	t.Helper()

	// normalize keywords like in the config package
	var keywords []string
	for _, k := range r.Keywords {
		keywords = append(keywords, strings.ToLower(k))
	}
	r.Keywords = keywords

	rules := make(map[string]config.Rule)
	rules[r.RuleID] = r
	d := detect.NewDetector(config.Config{
		Rules:    rules,
		Keywords: keywords,
	})

	if len(d.DetectString(falsePositive)) > 0 {
		t.Fatalf("False positive was detected by regex: %s", falsePositive)
	}
}
