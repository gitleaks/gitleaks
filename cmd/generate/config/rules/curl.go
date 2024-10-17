package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

// https://curl.se/docs/manpage.html#-u
func CurlBasicAuth() *config.Rule {
	r := config.Rule{
		RuleID: "curl-auth-user",
		// TODO: Description: "",
		Regex:    regexp.MustCompile(`\bcurl\b(?:.*|.*(?:[\r\n]{1,2}.*){1,5})[ \t\n\r](?:-u|--user)[ =](?:("[^:"]{3,}:[^"]{3,}")|('[^:']{3,}:[^']{3,}')|((?:"[^"]{3,}"|'[^']{3,}'|[\w$@.-]+):(?:"[^"]{3,}"|'[^']{3,}'|[\w$@.-]+))|)(?:\s|\z)`),
		Keywords: []string{"curl"},
		Allowlists: []config.Allowlist{
			{
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`[^:]+:(changeme|pass(word)?|pwd|\*+|x+)`),    // common placeholder passwords
					regexp.MustCompile(`<[^>]+>:<[^>]+>|<[^:]+:[^>]+>`),              // <placeholder>
					regexp.MustCompile(`[^:]+:\[[^]]+]`),                             // [placeholder]
					regexp.MustCompile(`(?i)[^:]+:\$(\d|[a-z]\w+|(\{\d|[a-z]\w+}))`), // $1 or $VARIABLE
				},
			},
		},
	}

	// validate
	tps := []string{
		// short
		`curl --cacert ca.crt -u elastic:P@ssw0rd$1 https://localhost:9200`, // same lines, no quotes
		`sh-5.0$ curl -k -X POST https://infinispan:11222/rest/v2/caches/default/hello \
  -H 'Content-type: text/plain' \
  -d 'world' \
  -u developer:yqDVtkqPECriaLRi`, // different line

		// long
		`curl --user roger23@gmail.com:pQ9wTxu4Fg https://www.dropbox.com/cli_link?host_id=abcdefg -v`, // same line, no quotes
		`curl -s --user 'api:d2LkV78zLx!t' \
    https://api.mailgun.net/v2/sandbox91d3515882ecfaa1c65be642.mailgun.org/messages`, // same line, single quotes
		`curl -s -v --user "j.smith:dB2yF6@qL9vZm1P#4J" "https://api.contoso.org/user/me"`, // same line, double quotes
		`curl -X POST --user "{acd3c08b-74e8-4f44-a2d0-80694le24f46}":"{ZqL5kVrX1n8tA2}" --header "Accept: application/json" --data "{\"text\":\"Hello, world\",\"source\":\"en\",\"target\":\"es\"}" https://gateway.watsonplatform.net/language-translator/api`,
		`curl --user kevin:'pRf7vG2h1L8nQkW9' -iX PATCH -H "Content-Type: application/json" -d`, // same line, mixed quoting
		`$ curl https://api.dropbox.com/oauth2/token \
  --user c28wlsosanujy2z:qgsnai0xokrw4j1 --data grant_type=authorization_code`, // different line

		// TODO
		//`     curl -s --insecure --url "imaps://whatever.imap.server" --user\
		//"myuserid:mypassword" --request "STATUS INBOX (UNSEEN)"`,
	}
	fps := []string{
		// short
		`   curl -sL --user "$1:$2" "$3" > "$4"`,                      // environment variable
		`curl -u <user:password> https://test.com/endpoint`,           // placeholder
		`curl --user neo4j:[PASSWORD] http://[IP]:7474/db/data/`,      // placeholder
		`curl -u "myusername" http://localhost:15130/api/check_user/`, // no password

		// long
		`           curl -sL --user "$GITHUB_USERNAME:$GITHUB_PASSWORD" "$GITHUB_URL" > "$TESTS_PATH"`,                                                             // environment variable
		`curl http://127.0.0.1:5000/file --user user:pass --digest        # digest auth`,                                                                           // placeholder
		`   curl -X GET --insecure --user "username:password" \`,                                                                                                   // placeholder
		`curl --silent --insecure --user ${f5user}:${f5pass} \`,                                                                                                    // placeholder
		`curl --insecure --ssl-reqd "smtps://smtp.gmail.com" --mail-from "src@gmail.com" --mail-rcpt "dst@gmail.com" --user "src@gmail.com" --upload-file out.txt`, // no password

		// different command
		`#HTTP command line test
curl -X POST -H "Content-Type: application/json" -d '{"id":12345,"geo":{"latitude":28.50,"longitude":-81.14}}' http://<ip>:8080/serve

#UDP command line test
echo -n '{"type":"serve","channel":"/","data":{"site_id":8,"post_id":12345,"geo":{"lat":28.50,"long":-81.14}}}' >/dev/udp/127.0.0.1/41234

#UDP Listener (for confirmation)
nc -u -l 41234`,
	}
	return utils.Validate(r, tps, fps)
}
