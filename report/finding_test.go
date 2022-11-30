package report

import "testing"

func TestRedact(t *testing.T) {
	tests := []struct {
		findings []Finding
		redact   bool
	}{
		{
			redact: true,
			findings: []Finding{
				{
					Secret: "line containing secret",
					Match:  "secret",
				},
			}},
	}
	for _, test := range tests {
		for _, f := range test.findings {
			f.Redact()
			if f.Secret != "REDACTED" {
				t.Error("redact not redacting: ", f.Secret)
			}
		}
	}
}
