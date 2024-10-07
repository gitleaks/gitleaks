package base

import (
	"testing"
)

func TestConfigAllowlistRegexes(t *testing.T) {
	tests := map[string]struct {
		invalid []string
		valid   []string
	}{
		"general placeholders": {
			invalid: []string{
				`true`, `True`, `false`, `False`, `null`, `NULL`,
			},
		},
		"interpolated variables - ansible": {
			invalid: []string{
				`{{ x }}`, `{{ password }}`, `{{password}}`, `{{ data.proxy_password }}`,
				`{{ dict1 | ansible.builtin.combine(dict2) }}`,
			},
		},
		"interpolated variables - github actions": {
			invalid: []string{
				`${{ env.First_Name }}`,
				`${{ env.DAY_OF_WEEK == 'Monday' }}`,
				`${{env.JAVA_VERSION}}`,
				`${{ github.event.issue.title }}`,
				`${{ github.repository == "Gattocrucco/lsqfitgp" }}`,
				`${{ github.event.pull_request.number || github.ref }}`,
				`${{ github.event_name == 'pull_request' && github.event.action == 'unassigned' }}`,
				`${{ secrets.SuperSecret }}`,
				`${{ vars.JOB_NAME }}`,
				`${{ vars.USE_VARIABLES == 'true' }}`,
			},
		},
		"interpolated variables - nuget": {
			invalid: []string{
				`%MY_PASSWORD%`, `%password%`,
			},
		},
		"interpolated variables - ucd": {
			invalid: []string{`@password@`, `@LDAP_PASS@`},
			valid:   []string{`@username@mastodon.example`},
		},
		"environment variables": {
			invalid: []string{`$2`, `$GIT_PASSWORD`, `${GIT_PASSWORD}`, `$password`},
			valid:   []string{`$yP@R.@=ibxI`, `$2a6WCust9aE`, `${not_complete1`},
		},
	}

	cfg := CreateGlobalConfig()
	allowlist := cfg.Allowlist
	for name, cases := range tests {
		t.Run(name, func(t *testing.T) {
			for _, c := range cases.invalid {
				if !allowlist.RegexAllowed(c) {
					t.Errorf("invalid value not marked as allowed: %s", c)
				}
			}

			for _, c := range cases.valid {
				if allowlist.RegexAllowed(c) {
					t.Errorf("valid value marked as allowed: %s", c)
				}
			}
		})
	}
}
