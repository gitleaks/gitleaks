// == WARNING ==
// These functions are used to generate GitLeak's default config.
// You are free to use these in your own project, HOWEVER, no API stability is guaranteed.

package utils

import (
	"github.com/rs/zerolog/log"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"strings"
)

func Validate(r config.Rule, truePositives []string, falsePositives []string) *config.Rule {
	// This is a hacky way to automatically set "IdentifierGroup".
	if strings.Contains(r.Regex.String(), "(?:=|>|:{1,3}=|\\|\\|:|<=|=>|:|\\?=)") {
		r.IdentifierGroup = 1
	}

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
	for _, tp := range truePositives {
		m := d.DetectString(tp)
		if len(m) < 1 {
			log.Fatal().
				Str("rule", r.RuleID).
				Str("value", tp).
				Str("regex", r.Regex.String()).
				Msg("Failed to Validate. True positive was not detected by regex.")
		}
	}
	for _, fp := range falsePositives {
		m := d.DetectString(fp)
		if len(m) != 0 {
			log.Fatal().
				Str("rule", r.RuleID).
				Str("value", fp).
				Str("identifier", m[0].Identifier).
				Str("secret", m[0].Secret).
				Str("regex", r.Regex.String()).
				Msg("Failed to Validate. False positive was detected by regex.")
		}
	}
	return &r
}

func ValidateWithPaths(r config.Rule, truePositives map[string]string, falsePositives map[string]string) *config.Rule {
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
	for path, tp := range truePositives {
		f := detect.Fragment{Raw: tp, FilePath: path}
		if len(d.Detect(f)) != 1 {
			log.Fatal().
				Str("rule", r.RuleID).
				Str("value", tp).
				Str("regex", r.Regex.String()).
				Str("path", r.Path.String()).
				Msg("Failed to Validate. True positive was not detected by regex and/or path.")
		}
	}
	for path, fp := range falsePositives {
		f := detect.Fragment{Raw: fp, FilePath: path}
		if len(d.Detect(f)) != 0 {
			log.Fatal().
				Str("rule", r.RuleID).
				Str("value", fp).
				Str("regex", r.Regex.String()).
				Str("path", r.Path.String()).
				Msg("Failed to Validate. False positive was detected by regex and/or path.")
		}
	}
	return &r
}
