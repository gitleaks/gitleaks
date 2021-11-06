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
					Line:    "line containing secret",
					Content: "secret",
				},
			}},
	}
	for _, test := range tests {
		for _, f := range test.findings {
			f.Redact()
			if f.Content != "REDACT" {
				t.Error("redact not redacting: ", f.Content)
			}
		}
	}
}
