package rules

import "testing"

// Regression test for #2354: generated rules must detect unquoted secrets
// followed by common delimiters, while generic-api-key keeps a narrower
// boundary to avoid matching ordinary identifiers followed by a comma.
func TestGeneratedRuleSecretSuffix(t *testing.T) {
	const (
		providerSecret = "ab3de5fg7hj9kl1mn3pq5rs7tu9vw1xy"
		genericSecret  = "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"
	)

	adafruit := AdafruitAPIKey().Regex
	generic := GenericCredential().Regex

	tests := []struct {
		name  string
		match func(string) bool
		input string
		want  bool
	}{
		{
			name:  "quoted query value",
			match: generic.MatchString,
			input: `url = "https://api.example.test/v1/items?api_key=` + genericSecret + `"`,
			want:  true,
		},
		{
			name:  "query value followed by ampersand",
			match: generic.MatchString,
			input: `https://api.example.test/v1/items?api_key=` + genericSecret + `&limit=10`,
			want:  true,
		},
		{
			name:  "env value",
			match: adafruit.MatchString,
			input: `ADAFRUIT_KEY=` + providerSecret,
			want:  true,
		},
		{
			name:  "env value followed by comma",
			match: adafruit.MatchString,
			input: `ADAFRUIT_KEY=` + providerSecret + `,`,
			want:  true,
		},
		{
			name:  "call argument",
			match: adafruit.MatchString,
			input: `connect(adafruit_key=` + providerSecret + `)`,
			want:  true,
		},
		{
			name:  "flow-style yaml",
			match: adafruit.MatchString,
			input: `{adafruit_key: ` + providerSecret + `}`,
			want:  true,
		},
		{
			name:  "generic comma is not a secret boundary",
			match: generic.MatchString,
			input: `api_key=` + genericSecret + `, other=identifier`,
			want:  false,
		},
		{
			name:  "generic closing parenthesis is not a secret boundary",
			match: generic.MatchString,
			input: `connect(api_key=` + genericSecret + `)`,
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.match(tt.input); got != tt.want {
				t.Errorf("MatchString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
