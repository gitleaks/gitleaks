package rules

import (
	b64 "encoding/base64"
	"fmt"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func JWT() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "JSON Web Token",
		RuleID:      "jwt",
		Regex:       generateUniqueTokenRegex(`ey[0-9a-z]{30,34}\.ey[0-9a-z-\/_]{30,500}\.[0-9a-zA-Z-\/_]{10,200}={0,2}`, true),
		Keywords:    []string{"ey"},
	}

	// validate
	tps := []string{`eyJhbGciOieeeiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwic3ViZSI6IjEyMzQ1Njc4OTAiLCJuYW1lZWEiOiJKb2huIERvZSIsInN1ZmV3YWZiIjoiMTIzNDU2Nzg5MCIsIm5hbWVmZWF3ZnciOiJKb2huIERvZSIsIm5hbWVhZmV3ZmEiOiJKb2huIERvZSIsInN1ZndhZndlYWIiOiIxMjM0NTY3ODkwIiwibmFtZWZ3YWYiOiJKb2huIERvZSIsInN1YmZ3YWYiOiIxMjM0NTY3ODkwIiwibmFtZndhZSI6IkpvaG4gRG9lIiwiaWZ3YWZhYXQiOjE1MTYyMzkwMjJ9.a_5icKBDo-8EjUlrfvz2k2k-FYaindQ0DEYNrlsnRG0==`, // gitleaks:allow
		`JWT := eyJhbGciOieeeiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwic3ViZSI6IjEyMzQ1Njc4OTAiLCJuYW1lZWEiOiJKb2huIERvZSIsInN1ZmV3YWZiIjoiMTIzNDU2Nzg5MCIsIm5hbWVmZWF3ZnciOiJKb2huIERvZSIsIm5hbWVhZmV3ZmEiOiJKb2huIERvZSIsInN1ZndhZndlYWIiOiIxMjM0NTY3ODkwIiwibmFtZWZ3YWYiOiJKb2huIERvZSIsInN1YmZ3YWYiOiIxMjM0NTY3ODkwIiwibmFtZndhZSI6IkpvaG4gRG9lIiwiaWZ3YWZhYXQiOjE1MTYyMzkwMjJ9.a_5icKBDo-8EjUlrfvz2k2k-FYaindQ0DEYNrlsnRG0`, // gitleaks:allow
	}
	return validate(r, tps, nil)
}

func JWTBase64() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "jwt-base64",
		Description: "Base64-encoded JSON Web Token",
		Regex: regexp.MustCompile(
			`\bZXlK(?:(?P<alg>aGJHY2lPaU)|(?P<apu>aGNIVWlPaU)|(?P<apv>aGNIWWlPaU)|(?P<aud>aGRXUWlPaU)|(?P<b64>aU5qUWlP)|(?P<crit>amNtbDBJanBi)|(?P<cty>amRIa2lPaU)|(?P<epk>bGNHc2lPbn)|(?P<enc>bGJtTWlPaU)|(?P<jku>cWEzVWlPaU)|(?P<jwk>cWQyc2lPb)|(?P<iss>cGMzTWlPaU)|(?P<iv>cGRpSTZJ)|(?P<kid>cmFXUWlP)|(?P<key_ops>clpYbGZiM0J6SWpwY)|(?P<kty>cmRIa2lPaUp)|(?P<nonce>dWIyNWpaU0k2)|(?P<p2c>d01tTWlP)|(?P<p2s>d01uTWlPaU)|(?P<ppt>d2NIUWlPaU)|(?P<sub>emRXSWlPaU)|(?P<svt>emRuUWlP)|(?P<tag>MFlXY2lPaU)|(?P<typ>MGVYQWlPaUp)|(?P<url>MWNtd2l)|(?P<use>MWMyVWlPaUp)|(?P<ver>MlpYSWlPaU)|(?P<version>MlpYSnphVzl1SWpv)|(?P<x>NElqb2)|(?P<x5c>NE5XTWlP)|(?P<x5t>NE5YUWlPaU)|(?P<x5ts256>NE5YUWpVekkxTmlJNkl)|(?P<x5u>NE5YVWlPaU)|(?P<zip>NmFYQWlPaU))[a-zA-Z0-9\/\\_+\-\r\n]{40,}={0,2}`),
		Keywords: []string{"zxlk"},
	}

	tps := generateTestValues()
	fps := []string{
		`-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG/MacGPG2 v2
Comment: GPGTools - https://gpgtools.org

mQENBFOrMNcBCAC+gLI4s3bUkobS5NpOQbWfjWXbqC0Ixpc5bZYDOvsmfstmswna
UWUXkRH9RONabzrAu4TGvW0f5DkC2fuWWHJhZWEccn+VE83+avMZN4/mzldSXPNX
A6F7+wHb1DjG+FCDcxMghkwDjGc16LOtZGufUo5iRQaC5pmNBOgDWdiObGPKOTEL
/uU8zLtKi2cibbkhRm22IGOzGyZMZN6zvEtPzlCp3eZEGMW0Ig+kbl6SaSDrSJNK
wElYcr/kJ9QF6CQ2iwZCGeL2jH5QaOi5uj1LXONpCd9nPeyDXc+Z20gXZiqkwRLc
IBPKza6hq/+4nwHBq8DNLv0W4xNC59jLbIhpABEBAAG0LEZyYW5rIE5vdGhhZnQg
PGZub3RoYWZ0QGFsdW1uaS5zdGFuZm9yZC5lZHU+iQE9BBMBCgAnBQJTqzDXAhsD
BQkHhh+ABQsJCAcDBRUKCQgLBRYCAwEAAh4BAheAAAoJECqYOYG1w7FJOr4IAK8x
ec4jbjd6jkKe0YJGdPzg6TM73ISV5VrUlJX7O3jgxHB4M8KIHN/8A/+ZxLk7WM96
iq0C8atWHkCkQBtNduWhzAFccQlpxrrb18T5/oItcrmX9Dx2H5WeIl4WAoqe0MTk
iMPv29RMMH9RJvXL0ihuuH4Z0VxV5nurI9QmGzG69QOzfP9qY1EfQEceO7OqXXvY
vvBEUbmWshLuHJ6tOQY5ib3+aLO7m+yJTgJ7s6DHBDqLhqJPW0g7jiJcrDhYXsoS
JMMhMdUhckeZfTXm1N3Dc+/t9/E8NZjdZ2q/ZZzvygC4mu0uihwBKFqoFvXCHRaW
Rf4uYxE+/Upna/mbXQi5AQ0EU6sw1wEIALSp9Cc4t/F2k+rwEfEMXihXLcLM9Dmh
ukz++kMSCSuq4QHE+I4rLda/lVSNJCXaXrGVkzJuzmpEeQFdhr6nLW9ZYhzK8FIc
YyfsYTQxXUVf5W4e/XfKNoG9lrwQd5XHxJTBJ57XjjoWJYPQ69NWH8622foOBpux
xewgR2LEFgl+ksu7aQL4cQif6D3dko3EiIf1t0LDBXxFEREFCg+vkDFsDIW5bdaI
mDYwewGj7dAPLuo0sx1We+uBxb+j30xw/ASDOBhO3ratQWs+4w2FC7gw7cuf0CJC
/hMEw8nloGsIbqBmAnLdlQBxkfFG9DqRBNdSUM8xI66F0eGaaPHJ/S8AEQEAAYkB
JQQYAQoADwUCU6sw1wIbDAUJB4YfgAAKCRAqmDmBtcOxSZvvB/4w6S5YZQUmDVYK
9HPOm49qWxGPd5dLHr2g388sJ4LDK98Q9oicHgf2R35OXTyqhv4kFJL3eukQ6oLW
QOqQKLRycrQUu7eSESAiVmJ1gbuXLAWJmvUABGSYzj3BjWQRexYW/MZ51XqNftF9
oOSAoFWrdqeJbHoxPTXIb6P8EWk4Ei2j2bSIfBBSbBMSB6Kfk9IjpISM8+97RS5o
6605rmM5MY1Lz8cq8AZIYJs/MnUCZrpQ0c9QSWrflHAeWAy6xMGfdSynbEExQ4z8
AIfKWMro74nRFbAnv/BzrF2R8uHmdE7T6q9ZZsAydlaxQbdmyhCeGAdw93CwAypb
vHVobJ8A
=mIC1
-----END PGP PUBLIC KEY BLOCK-----`,
	}
	return validate(r, tps, fps)
}

func generateTestValues() []string {
	// Sample JWT from RFC-7519
	jwtSuffix := ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// Validate known header parameters
	// https://www.iana.org/assignments/jose/jose.xhtml
	headers := map[string][]string{
		"alg": {
			`"ES256"`,
			`"ES384"`,
			`"ES512"`,
			`"ECDH-ES"`,
			`"HS256"`,
			`"HS384"`,
			`"HS512"`,
			`"RS256"`,
			`"RS384"`,
			`"RS512"`,
			`"PS256"`,
			`"PS384"`, `"PS512"`,
			`"none"`,
			// Nonstandard
			`"A128KW"`,
			`"ECDH-ES+A256KW"`,
			`"RSA-OAEP"`,
		},
		"apu":     {`"Tx9qG69ZfodhRos-8qfhTPc6ZFnNUcgNDVdHqX1UR3s"`, `"RfXdxTfIzilWBzWWX3ovHBDzgDcLNy0BFJWSxa0dqnw"`},
		"apv":     {`"ZGlkOmVsZW06cm9wc3RlbjpFa"`, `"ZGlkOmtleTp6Nk1rak1TWWF1dU1neDlhekV5VW5UVzVvNWpGUmtiQnU1VDgzZjM5dU53bnNHbW0jejZMU29HdFpTclVNWnVkQWFnekVmWWY3azhqSFpjR0Q3OVNveDd2NHdDa0RLTlN3"`},
		"aud":     {`"https://vault.example.com"`, `"http://example.com"`},
		"b64":     {`true`, `false`},
		"crit":    {`["exp"]`},
		"cty":     {`"example"`, `"json"`},
		"epk":     {`{"crv":"X25519","kty":"OKP","x":"Tx9qG69ZfodhRos-8qfhTPc6ZFnNUcgNDVdHqX1UR3s"}`, `{"kty":"OKP","crv":"X25519","x":"RfXdxTfIzilWBzWWX3ovHBDzgDcLNy0BFJWSxa0dqnw"}`},
		"enc":     {`"A256GCM"`, `"A256CBC-HS512"`, `"A128CBC-HS256"`},
		"jku":     {`"https://c2id.com/jwks.json"`},
		"jwk":     {`{"crv":"P-256","kid":"DB2X:GSG2:72H3:AE3R:KCMI:Y77E:W7TF:ERHK:V5HR:JJ2Y:YMS6:HFGJ","kty":"EC","x":"jyr9-xZBorSC9fhqNsmfU_Ud31wbaZ-bVGz0HmySvbQ","y":"vkE6qZCCvYRWjSUwgAOvibQx_s8FipYkAiHS0VnAFNs"}`, `{"kty":"RSA","n":"jyTwiSJACtW_SW-aiihQS5Y5QR704zUwjhlevY0oK-y5wP7SlIc2hq2OPVRarCzjhOxZl2AQFzM5VCR7xRDcnIn9t_pl7Mgsnx9hKDS9yQ24YXzhQ4cMEVVuqwcHvXqPdWDSoCZ1ccMqiiPyBSNGQTXMPY5PBxMOR47XwOb4eNMOPqnzVio3MEtL2wphtEonP3MY6pxJJzzel04wSCRZ4n06reqwER3KwRFPnRpRxAgmSEot5IBLIT3jj-amT5sD7YoUDbPmLk23zgDBIhX88fkClilg1W-fUi1XxYZomEPGvV7OrE1yszt4YDPqKgjJT8t2JPy__1ri-8rZgSxn5Q","e":"AQAB"`},
		"iss":     {`"http://localhost:8087/realms/grafana"`, `"kubernetes/serviceaccount"`},
		"iv":      {`"zjJPRrj0TGez9JYkChTrB3iqKoDkiBhn"`, `"10PlAIteHLVABtt"`},
		"kid":     {`"my_key_id"`, `"did:example:123#zC1Rnuvw9rVa6E5TKF4uQVRuQuaCpVgB81Um2u17Fu7UK"`},
		"key_ops": {`["sign"]`, `["decrypt"]`, `["encrypt"]`},
		"kty":     {`"EC"`, `"RSA"`},
		"nonce":   {`"Os_sBjfWzVZenwwjvLrwXA"`, `"LDDZAGcBuKYpuNlFTCxPYw"`},
		"p2c":     {`4096`, `1000`},
		"p2s":     {`"c_ORk4HSsqZD2LvVeCUHqg"`},
		"ppt":     {`"foo"`},
		"sub":     {`"project_path:my-group/my-project:ref_type:branch:ref:feature-branch-1"`, `"1234567890"`},
		// I cannot find any real-world examples of the svt header
		// and the RFC doesn't seem to explicitly state the content.
		"svt":      {``},
		"tag":      {`"h6mJqHn33oCsDd5X57MI-g"`},
		"typ":      {`"JWT"`, `"JWK"`, `"JSOE"`, `"JSON"`, `"plain"`},
		"url":      {`"https://example.com"`},
		"use":      {`"enc"`, `"sig"`},
		"ver":      {`"2"`, `"3"`},
		"version":  {`"2"`, `"3"`},
		"x5c":      {`["MIICmzCCAYMCBgF4HR7HNDANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjEwMzEwMTcwOTE5WhcNMzEwMzEwMTcxMDU5WjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCpLzXHp8i09R2HU5YJPyncC4tiAWWmaDrVZenqynWlWKOjIXb0Y5JoP3ET68u16Bf7mHQGc/u9rRvCw4A92HpJ15WyUSJ80YcK0gPTE0Woc1ZxdK3h4t9AoA8VSrROwQ77w/VAdGrrJ4bwkAVrFqSRpqAsW5XxV3/bU8YkVaG8mh0kuFf/5ib0vxdSkg+mz+ZCuIxQ5YN77kNaMecO19XuaBo7FsG9WjfCPxXYuajkuLgdptPgwTN4np70h0WjaSP/jhjL2ixf48w+27wFDP+ic+B/TCOtVa3fj1GPo6RLxHGU0Zh64jFhmvRM6E/kX7IQ+FJcOwp1VPA9/vMABopAgMBAAEwDQYJKoZIhvcNAQELBQADggEBALILq1Z4oQNJZEUt24VZcvknsWtQtvPxl3JNcBQgDR5/IMgl5VndRZ9OT56KUqrR5xRsWiCvh5Lgv4fUEzAAo9ToiPLub1SKP063zWrvfgi3YZ19bty0iXFm7l2cpQ3ejFV7WpcdLJE0lapFdPLo6QaRdgNu/1p4vbYg7zSK1fQ0OY5b3ajhAx/bhWlrN685owRbO5/r4rUOa6oo9l4Qn7jUxKUx4rcoe7zUM7qrpOPqKvn0DBp3n1/+9pOZXCjIfZGvYwP5NhzBDCkRzaXcJHlOqWzMBzyovVrzVmUilBcj+EsTYJs0gVXKzduX5zO6YWhFs23lu7AijdkxTY65YM0="]`},
		"x5t":      {`"IYIeevIT57t8ppUejM42Bqx6f3I"`},
		"x5t#S256": {`"TuOrBy2NcTlFSWuZ8Kh8W8AjQagb4fnfP1SlKMO8-So"`},
		"x5u":      {`"https://tel.example.org/passport.cer"`},
		"zip":      {`"DEF"`},
	}

	var examples []string
	for key, values := range headers {
		for _, value := range values {
			header := fmt.Sprintf(`{"%s":%s}`, key, value)
			jwt := []byte(b64.RawURLEncoding.EncodeToString([]byte(header)) + jwtSuffix)
			examples = append(examples, b64.StdEncoding.EncodeToString(jwt))
			examples = append(examples, b64.RawStdEncoding.EncodeToString(jwt))
			examples = append(examples, b64.URLEncoding.EncodeToString(jwt))
			examples = append(examples, b64.RawURLEncoding.EncodeToString(jwt))
		}
	}
	return examples
}
