package base

import (
	"testing"
)

var allowlistRegexTests = map[string]struct {
	invalid []string
	valid   []string
}{
	"general placeholders": {
		invalid: []string{
			`true`, `True`, `false`, `False`, `null`, `NULL`,
		},
	},
	"general placeholders - repeated characters": {
		invalid: []string{
			// full
			`aaaaaaaaaaaaaaaaa`, `BBBBBBBBBBbBBBBBBBbBB`, `00000000000000000000000000000000`, `********************`, `.................`,
			// partial
			`ACCAXXXXXXXXXXXXXXXX`, `ico-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`,
		},
		valid: []string{
			// These obviously aren't valid, but if we do partial matches we could inadvertently skip the other examples.
			`aaaaaaaaaaaaaaaaaaabaa`, `pas*************d`, `glsa_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_AAAAAAAA`,
			`ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2JuV3z0fopWIkb+T69ORpeMlnW/7GXFTBhrvNCfnAVgVteVDGeQphYj5zhg8AybuaMiC5IBHM6LOgUNNzp5lBeNb5fTCcrEHYGWGkw0aAU3O1YBZQsyx`,
			`-----BEGIN PGP PUBLIC KEY BLOCK-----
mQENBEznhOQBCADZZh6L+9YH/bjmhQAuqeZUvk9y/Q8GZNMYpLx9accXabL8fnnG
Uu1CERympAKZmSdVvPIuRapAcLJVh/m+i+eQo7QQW8jiT4TwtivfsjPm+gqqyDyL
SFrbgXDCT32q4baAUoowfVP+stKpnTZLuthuh++DOZfJKKj4p6dy3qUEQf769lWq
oEzS6dHdtJrTLw6h5ORTpZrK4pLyo7w3BlxT4lso+a/BXFiWyQz17m2h63mNUDql
Q6KahO66jJg0veYsKrziMkaDO/yglMcOXMNoFQVh3ZpYq6oT+7LSfU9u0p1J7BnN
6fTZC9c8pTz707xJQWHjsKW8sBkI0iqVmVBpABEBAAG0MURhbWllbiBSZWdhZCAo
TWFudGlzQlQgZGV2KSA8ZHJfbWFudGlzQHJlZ2FkLm9yZz6JATgEEwECACIFAlCd
j8YCGwMGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEA/+d/t+CBBf5hsIALt2
5cm4Qgz3eXTSSn0+Zb/6rf76IcuVrRCtF6G38g9sKvO1TOqAy1wrQOsmBmewKrC/
89ku9nnZv7rWfwNCo/9LJPQQAy/wdse6jOjeWrSun8Zns+0NZilRvt4e4K9QvMO1
pJDUQGF72wrexYlDXhtlPfkdk2OJ0yEVBsUZPOMF9Z53YMqOsA3geMaphL10U/Tq
nOiDfY10R/4HQYKlp2waCKjKU8NqqpvNnsQleuwJA352/BDgr5CINKm8Je9BoIzK
dOsf2LscXYAqPnyd9eD/h3SHVMuE+7+R6yORYjAkOANU8bgcEjrKlDPqG3TW9Zkl
FwGROcjQxn9MlDVQZHOJAU8EEwECADkCGwMGCwkIBwMCBhUIAgkKCwQWAgMBAh4B
AheAFiEE6qY/HyhMqPUVN0kHD/53+34IEF8FAl6kD/QACgkQD/53+34IEF+E7gf/
ed+ANT3T9wqTZLo5TTRZugdolb6PfqOn7H3LTUosrXEEPXWXIi1invTGI/Zp+Xs4
bjXZUe0+mzfa+9hCqhAUyRkSuVfi/rDi/UbTBnlIgsFvbVbGRgiMOEKR+xtr7sQl
T7DOQKfXKpZa+QdzPR9LenmhK1UYVk6NA93B7oc9kRj4ff4KHCO6Vol47OK+xaki
ETr8S8SAIgXDFtCi5TBR4mUO7QUaIsBpPsT1PNw98gc7mr/Mm7cjES5gKhlEnDWk
G7YvtzCi6K/zMTQWdtrqhXckRIhXNcxWxSkNehMQ0DGRg838uYQnmdl7v+N/d8xt
co6tfsyLLxS1vu00N4ZRy9HdZN1iARAAAQEAAAAAAAAAAAAAAAD/2P/gABBKRklG
AAEBAAABAAEAAP/+AD5DUkVBVE9SOiBnZC1qcGVnIHYxLjAgKHVzaW5nIElKRyBK
UEVHIHY2MiksIGRlZmF1bHQgcXVhbGl0eQr/2wBDAAgGBgcGBQgHBwcJCQgKDBQN
-----END PGP PUBLIC KEY BLOCK-----`,
		},
	},
	"general placeholders - repeated sequences": {
		invalid: []string{
			`LR134894112312312312312312312`,
			`01234567890123456789012345678901`, `1234567890123456789012345678901`,
		},
	},
	"environment variables": {
		invalid: []string{`$2`, `$GIT_PASSWORD`, `${GIT_PASSWORD}`, `$password`},
		valid:   []string{`$yP@R.@=ibxI`, `$2a6WCust9aE`, `${not_complete1`},
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
	"interpolated variables - string fmt - golang": {
		invalid: []string{
			`%b`, `%c`, `%d`, `% d`, `%e`, `%E`, `%f`, `%F`, `%g`, `%G`, `%o`, `%O`, `%p`, `%q`, `%-s`, `%s`, `%t`, `%T`, `%U`, `%#U`, `%+v`, `%#v`, `%v`, `%x`, `%X`,
		},
	},
	"interpolated variables - string fmt - python": {
		invalid: []string{
			`{}`, `{0}`, `{10}`,
		},
	},
	"interpolated variables - ucd": {
		invalid: []string{`@password@`, `@LDAP_PASS@`},
		valid:   []string{`@username@mastodon.example`},
	},
	"miscellaneous - file paths": {
		invalid: []string{
			// MacOS
			`/Users/james/Projects/SwiftCode/build/Release`,
			// Linux
			`/tmp/screen-exchange`,
		},
		valid: []string{},
	},
}

func TestConfigAllowlistRegexes(t *testing.T) {
	cfg := CreateGlobalConfig()
	allowlists := cfg.Allowlists
	for name, cases := range allowlistRegexTests {
		t.Run(name, func(t *testing.T) {
			for _, c := range cases.invalid {
				for _, a := range allowlists {
					if !a.RegexAllowed(c) {
						t.Errorf("invalid value not marked as allowed: %s", c)
					}
				}
			}

			for _, c := range cases.valid {
				for _, a := range allowlists {
					if a.RegexAllowed(c) {
						t.Errorf("valid value marked as allowed: %s", c)
					}
				}
			}
		})
	}
}

func BenchmarkConfigAllowlistRegexes(b *testing.B) {
	cfg := CreateGlobalConfig()
	allowlists := cfg.Allowlists
	for n := 0; n < b.N; n++ {
		for _, cases := range allowlistRegexTests {
			for _, c := range cases.invalid {
				for _, a := range allowlists {
					a.RegexAllowed(c)
				}
			}

			for _, c := range cases.valid {
				for _, a := range allowlists {
					a.RegexAllowed(c)
				}
			}
		}
	}
}

var allowlistPathsTests = map[string]struct {
	invalid []string
	valid   []string
}{
	"javascript - common static assets": {
		invalid: []string{
			`tests/e2e/nuget/wwwroot/lib/bootstrap/dist/js/bootstrap.esm.min.js`,
			`src/main/static/lib/angular.1.2.16.min.js`,
			`src/main/resources/static/jquery-ui-1.12.1/jquery-ui-min.js`,
			`src/main/resources/static/js/jquery-ui-1.10.4.min.js`,
			`src-static/js/plotly.min.js`,
			`swagger/swaggerui/swagger-ui-bundle.js.map`,
			`swagger/swaggerui/swagger-ui-es-bundle.js.map`,
			`src/main/static/swagger-ui.min.js`,
			`swagger/swaggerui/swagger-ui.js`,
		},
	},
	"python": {
		invalid: []string{
			// lock files
			`Pipfile.lock`, `poetry.lock`,
			// virtual environments
			"env/lib/python3.7/site-packages/urllib3/util/url.py",
			"venv/Lib/site-packages/regex-2018.08.29.dist-info/DESCRIPTION.rst",
			"venv/lib64/python3.5/site-packages/pynvml.py",
			"python/python3/virtualenv/Lib/site-packages/pyphonetics/utils.py",
			"virtualenv/lib64/python3.7/base64.py",
			// packages
			"cde-root/usr/lib64/python2.4/site-packages/Numeric.pth",
			"lib/python3.9/site-packages/setuptools/_distutils/msvccompiler.py",
			"lib/python3.8/site-packages/botocore/data/alexaforbusiness/2017-11-09/service-2.json",
			"code/python/3.7.4/Lib/site-packages/dask/bytes/tests/test_bytes_utils.py",
			"python/3.7.4/Lib/site-packages/fsspec/utils.py",
			"python/2.7.16.32/Lib/bsddb/test/test_dbenv.py",
			"python/lib/python3.8/site-packages/boto3/data/ec2/2016-04-01/resources-1.json",
			// distinfo
			"libs/PyX-0.15.dist-info/AUTHORS",
		},
	},
}

func TestConfigAllowlistPaths(t *testing.T) {
	cfg := CreateGlobalConfig()
	allowlists := cfg.Allowlists
	for name, cases := range allowlistPathsTests {
		t.Run(name, func(t *testing.T) {
			for _, c := range cases.invalid {
				for _, a := range allowlists {
					if !a.PathAllowed(c) {
						t.Errorf("invalid path not marked as allowed: %s", c)
					}
				}
			}

			for _, c := range cases.valid {
				for _, a := range allowlists {
					if a.PathAllowed(c) {
						t.Errorf("valid path marked as allowed: %s", c)
					}
				}
			}
		})
	}
}

func BenchmarkConfigAllowlistPaths(b *testing.B) {
	cfg := CreateGlobalConfig()
	allowlists := cfg.Allowlists
	for n := 0; n < b.N; n++ {
		for _, cases := range allowlistPathsTests {
			for _, c := range cases.invalid {
				for _, a := range allowlists {
					a.PathAllowed(c)
				}
			}

			for _, c := range cases.valid {
				for _, a := range allowlists {
					a.PathAllowed(c)
				}
			}
		}
	}
}
