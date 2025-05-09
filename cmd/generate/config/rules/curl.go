package rules

import (
	"fmt"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

// https://curl.se/docs/manpage.html#-u
func CurlBasicAuth() *config.Rule {
	r := config.Rule{
		RuleID:      "curl-auth-user",
		Description: "Discovered a potential basic authorization token provided in a curl command, which could compromise the curl accessed resource.",
		Regex:       regexp.MustCompile(`\bcurl\b(?:.*|.*(?:[\r\n]{1,2}.*){1,5})[ \t\n\r](?:-u|--user)(?:=|[ \t]{0,5})("(:[^"]{3,}|[^:"]{3,}:|[^:"]{3,}:[^"]{3,})"|'([^:']{3,}:[^']{3,})'|((?:"[^"]{3,}"|'[^']{3,}'|[\w$@.-]+):(?:"[^"]{3,}"|'[^']{3,}'|[\w${}@.-]+)))(?:\s|\z)`),
		Keywords:    []string{"curl"},
		Entropy:     2,
		Allowlists: []*config.Allowlist{
			{
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`[^:]+:(?:change(?:it|me)|pass(?:word)?|pwd|test|token|\*+|x+)`), // common placeholder passwords
					regexp.MustCompile(`['"]?<[^>]+>['"]?:['"]?<[^>]+>|<[^:]+:[^>]+>['"]?`),             // <placeholder>
					regexp.MustCompile(`[^:]+:\[[^]]+]`),                                                // [placeholder]
					regexp.MustCompile(`['"]?[^:]+['"]?:['"]?\$(?:\d|\w+|\{(?:\d|\w+)})['"]?`),          // $1 or $VARIABLE
					regexp.MustCompile(`\$\([^)]+\):\$\([^)]+\)`),                                       // $(cat login.txt)
					regexp.MustCompile(`['"]?\$?{{[^}]+}}['"]?:['"]?\$?{{[^}]+}}['"]?`),                 // ${{ secrets.FOO }} or {{ .Values.foo }}
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
		`curl -u ":d2LkV78zLx!t" https://localhost:9200`, // empty username
		`curl -u "d2LkV78zLx!t:" https://localhost:9200`, // empty password

		// long
		`curl -sw '%{http_code}' -X POST --user  'johns:h0pk1ns~21s' $GItHUB_API_URL/$GIT_COMMIT --data`,
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
		`curl -i -u 'test:test'`,
		`   curl -sL --user "$1:$2" "$3" > "$4"`,                      // environment variable
		`curl -u <user:password> https://test.com/endpoint`,           // placeholder
		`curl --user neo4j:[PASSWORD] http://[IP]:7474/db/data/`,      // placeholder
		`curl -u "myusername" http://localhost:15130/api/check_user/`, // no password
		`curl -u username:token`,
		`curl -u "${_username}:${_password}"`,
		`curl -u "${username}":"${password}"`,
		`curl -k -X POST -I -u "SRVC_JENKINS:${APPID}"`,
		`curl -u ":" https://localhost:9200`, // empty username and password

		// long
		`curl -sw '%{http_code}' -X POST --user '$USERNAME:$PASSWORD' $GItHUB_API_URL/$GIT_COMMIT --data`,
		`curl --user "xxx:yyy"`,
		`           curl -sL --user "$GITHUB_USERNAME:$GITHUB_PASSWORD" "$GITHUB_URL" > "$TESTS_PATH"`, // environment variable
		// variable interpolation
		`curl --silent --fail {{- if and $.Values.username $.Values.password }} --user "{{ $.Values.username }}:{{ $.Values.password }}"`,
		`curl -XGET -i -u "${{ env.ELK_ID }}:${{ build.env.ELK_PASS }}"`,
		`curl -XGET -i -u "${{needs.vault.outputs.account_id}}:${{needs.vault.outputs.account_password}}"`,
		`curl -XGET -i -u "${{ steps.vault.outputs.account_id }}:${{ steps.vault.outputs.account_password }}"`,
		`curl -X POST --user "$(cat ./login.txt):$(cat ./password.txt)"`,                                                                                           // command
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

// https://curl.se/docs/manpage.html#-H
func CurlHeaderAuth() *config.Rule {
	// language=regexp
	authPat := `(?i)(?:Authorization:[ \t]{0,5}(?:Basic[ \t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \t]([\w=~@.+/-]{8,})|([\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \t]{0,5}([\w=~@.+/-]{8,}))`
	r := config.Rule{
		RuleID:      "curl-auth-header",
		Description: "Discovered a potential authorization token provided in a curl command header, which could compromise the curl accessed resource.",
		Regex: regexp.MustCompile(
			// language=regexp
			fmt.Sprintf(`\bcurl\b(?:.*?|.*?(?:[\r\n]{1,2}.*?){1,5})[ \t\n\r](?:-H|--header)(?:=|[ \t]{0,5})(?:"%s"|'%s')(?:\B|\s|\z)`, authPat, authPat)),
		Entropy:  2.75,
		Keywords: []string{"curl"},
		//Allowlists: []*config.Allowlist{
		//	{
		//		Regexes: []*regexp.Regexp{},
		//	},
		//},
	}

	tps := []string{
		`curl --header  'Authorization:  5eb4223e-5008-46e5-be67-c7b8f2732305'`,
		// Short flag.
		`curl -H 'Authorization: Basic YnJvd3Nlcjo=' \`, // same line, single quotes
		// TODO: Handle short flags combined.
		//`TOKEN=$(curl -sH "Authorization: Basic $BASIC_TOKEN" "https://$REGISTRY/oauth2/token?service=$REGISTRY&scope=repository:$REPO:pull" | jq -r .access_token)`,

		// Long flag.
		`curl -k -X POST --header "Authorization: Basic djJlNEpYa0NJUHZ5a2FWT0VRXzRqZmZUdDkwYTp2emNBZGFzZWpmlWZiUDc2VUJjNDNNVDExclVh" "https://api-qa.example.com:8243/token" -d "grant_type=client_credentials"`, // same line, double quotes

		// Basic auth.
		`curl -X POST -H "Content-Type: application/json" \
 -H "Authorization: Basic MzUzYjMwMmM0NDU3NGY1NjUwNDU2ODdlNTM0ZTdkNmE6Mjg2OTI0Njk3ZTYxNWE2NzJhNjQ2YTQ5MzU0NTY0NmM=" \
  -d '{"user":{"emailAddress":"test@example.com"}, "password":"password"}' \
  'http://localhost:8080/oauth2-provider/v1.0/users'`, // different line, double quotes
		`#curl -X POST \
#  https://api.mailgun.net/v3/sandbox7dbcabccd4314c123e8b23599d35f5b6.mailgun.org/messages \
#  -H 'Authorization: Basic YXBpOmtleS1hN2MzNDJ3MzNhNWQxLTU2M2U3MjlwLTZhYjI3YzYzNzM0Ng==' \
#  -F from='Excited User <mailgun@sandbox7dbc123bccd4314c0aae8b23599d35f5b6.mailgun.org>' \
#  -F to='joe@example.com' \
#  -F subject='Hello' \
#  -F text='Testing some Mailgun awesomness!'`, // different line, single quotes

		// Bearer auth
		`# curl -X GET "http://localhost:3000/api/cron/status" -H "Authorization: Bearer cfcabd11c7ed9a41b1a3e063c32d5114"`, // same line, double quotes
		`curl -X PUT -H 'Authorization: Bearer jC+6TUUjCNHcVtAXpcqBCgxnA8r+qD6MatnYaf/+289y7HWpK0BWPyLHv/K4DMN32fufwmeVVjlo8zjgBh8kx3GfS6IqO70w1DVMSCTwX7fhEpiXaxzv0mhSMHDX9Kw63Q6DkavUWUV+MDNhCF5wGQrcdQNncVRF3YkuDHDT/xw2YWyZ/DX8k+gAYiC8gcD8Ueg0ljBVS1IDwPjuGoFPESJVxYr0MDPF2D8Pn2S5rq692U4D9ZLuluS46VA4DK6ig5P7QM5XVXi4V7vXM8qpN/zqneyz+w4PUh6NIX7QG6JczMhYd9maWRWVat5jDdyII63P6sNAy9QZjw+ClW211Q==' -d 'user={"account":"user@domain.com", "roles":["user"]}' http://127.0.0.1:8443/desks/1/occupy`, // same line, single quotes
		`curl https://api.openai.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer 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" \`, // different line, double quotes
		`curl -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
     -H "Authorization: Bearer _FXNljbSRYMWx3TWrd7lgKhLtVZX6iskC8Wcbb4b" \
     -H "Content-Type:application/json"`,
		`curl -H "Authorization: Bearer sha256~bRLFnzd59Z3XpZH5_seJPHALOuvbWiKwbFKSsoALkgp"`,

		// Token auth
		`curl -H "Authorization: Api-Token 22cb987851bc5659l29114c62e60c79abd0d2c08" --request PUT https://appsecclass.report/api/use/635`, // token
		`curl -H "Authorization: Token 22cb987851bc5659229114c62e60c79abd0d2c08" --request PUT https://appsecclass.report/api/use/635`,     // token

		// Nothing
		`curl -L -H "Authorization:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjb25maWRlbmNlIjowLjh9.kvRPfjAhLhtRTczoRgctVGp7KY1QVH3UBZM-gM0x8ec" service1.local -> correct jwt `, // no prefix
		`curl -L -H "Authorization: sha256~bRLFnzd5@=-.a+/hgdS"`, // no prefix

		// Non-authorization headers.
		`curl -X GET \
     -H "apikey: c4ed6c21-9dd5-4a05-8e3f-c56d1151cce8" \
     -H "Accept: application/json" \`, // apikey
		`curl -X POST --header "Api-Token: Sk94HG7f6KB"`, // api-token
		`curl -XPOST http://localhost:8080/api/tasks -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" -H "Token: 3fea6af1349166ea" -d "content=hello-curl"`, // token
		`curl -X GET https://octopus.corp.net/
     -H "X-Octopus-ApiKey: 3a16750d-d363-41a4-8ebd-035408f7730f" \`, // X-$thing-ApiKey
	}
	fps := []string{
		// Placeholders
		`curl https://example.com/micropub -d h=entry -d "content=Hello World" -H "Authorization: Bearer XXXXXXXXXXXX"`,
		`curl -X POST https://accounts.spotify.com/api/token -d grant_type=client_credentials --header "Authorization: Basic ..."`,
		`curl \
  -H "Authorization: Bearer <Openverse API token>" \
  "https://api.openverse.org/v1/audio/?q=test"`,
		`curl -v -v -v -X POST https://domain/api/v1/authentication/sso/login-url/ \
  -H 'Content-Type: application/json' \
  -H "Authorization: Token **********" \
  -d '{"username": "test", "next": "/luna/"}'`,

		// Variables
		`curl -XPOST http://localhost:8080/api/token -H "Authorization: basic {base64(email:password[\n])}" => token`, // same line, invalid base64
		`curl -X GET \
     -H "apikey: $API_KEY" \
     -H "Accept: $FORMAT" \
"$API_URL/rest/v1/stats_derniere_labellisation"`, // API Key placeholder
		`$ curl -X POST "http://localhost:8000/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -d '{
        "model": "chatglm3-6b-32k",
        "messages": [{"role": "system", "content": "You are a helpful assistant."}, {"role": "user", "content": "Hello!"}]
    }'`, // different line, placeholder
		`curl -X GET -H "Content-Type: application/json" -H "Authorization: Bearer $(gcloud auth print-access-token)" https://workflowexecutions.googleapis.com/v1/projects/244283331594/locations/us-central1/workflows/sample-workflow/executions/43c925aa-514a-44c1-a0a4-a9f8f26fd2cb/callbacks/1705791f-d446-4e92-a6d0-a13622422e80_31864a51-8c13-4b03-ad4d-945cdc8d0631`, // script

		// Not valid BASIC
		`curl -X POST -H "Content-Type: application/json" -H "Authorization: Basic eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjb25maWRlbmNlIjowLjh9.kvRPfjAhLhtRTczoRgctVGp7KY1QVH3UBZM-gM0x8ec" \`,
	}
	return utils.Validate(r, tps, fps)
}
