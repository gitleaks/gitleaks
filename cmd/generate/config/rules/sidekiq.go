package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func SidekiqSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a Sidekiq Secret, which could lead to compromised background job processing and application data breaches.",
		RuleID:      "sidekiq-secret",

		Regex: generateSemiGenericRegex([]string{"BUNDLE_ENTERPRISE__CONTRIBSYS__COM", "BUNDLE_GEMS__CONTRIBSYS__COM"},
			`[a-f0-9]{8}:[a-f0-9]{8}`, true),
		Keywords: []string{"BUNDLE_ENTERPRISE__CONTRIBSYS__COM", "BUNDLE_GEMS__CONTRIBSYS__COM"},
	}

	// validate
	tps := []string{
		"BUNDLE_ENTERPRISE__CONTRIBSYS__COM: cafebabe:deadbeef",
		"export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef",
		"export BUNDLE_ENTERPRISE__CONTRIBSYS__COM = cafebabe:deadbeef",
		"BUNDLE_GEMS__CONTRIBSYS__COM: \"cafebabe:deadbeef\"",
		"export BUNDLE_GEMS__CONTRIBSYS__COM=\"cafebabe:deadbeef\"",
		"export BUNDLE_GEMS__CONTRIBSYS__COM = \"cafebabe:deadbeef\"",
		"export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef;",
		"export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef && echo 'hello world'",
	}
	return validate(r, tps, nil)
}

func SidekiqSensitiveUrl() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a Sidekiq Sensitive URL, potentially exposing internal job queues and sensitive operation details.",
		RuleID:      "sidekiq-sensitive-url",
		SecretGroup: 2,
		Regex:       regexp.MustCompile(`(?i)\b(http(?:s??):\/\/)([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)(?:[\/|\#|\?|:]|$)`),
		Keywords:    []string{"gems.contribsys.com", "enterprise.contribsys.com"},
	}

	// validate
	tps := []string{
		"https://cafebabe:deadbeef@gems.contribsys.com/",
		"https://cafebabe:deadbeef@gems.contribsys.com",
		"https://cafeb4b3:d3adb33f@enterprise.contribsys.com/",
		"https://cafeb4b3:d3adb33f@enterprise.contribsys.com",
		"http://cafebabe:deadbeef@gems.contribsys.com/",
		"http://cafebabe:deadbeef@gems.contribsys.com",
		"http://cafeb4b3:d3adb33f@enterprise.contribsys.com/",
		"http://cafeb4b3:d3adb33f@enterprise.contribsys.com",
		"http://cafeb4b3:d3adb33f@enterprise.contribsys.com#heading1",
		"http://cafeb4b3:d3adb33f@enterprise.contribsys.com?param1=true&param2=false",
		"http://cafeb4b3:d3adb33f@enterprise.contribsys.com:80",
		"http://cafeb4b3:d3adb33f@enterprise.contribsys.com:80/path?param1=true&param2=false#heading1",
	}
	return validate(r, tps, nil)
}
