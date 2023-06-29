package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func SumoLogicAccessID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sumologic-access-id",
		Description: "SumoLogic Access ID",
		// TODO: Make 'su' case-sensitive.
		Regex: generateSemiGenericRegex([]string{"sumo"},
			"su[a-zA-Z0-9]{12}", false),
		SecretGroup: 1,
		Entropy:     3,
		Keywords: []string{
			"sumo",
		},
		Allowlist: config.Allowlist{
			RegexTarget: "line",
			Regexes: []*regexp.Regexp{
				regexp.MustCompile(`sumOf`),
			},
		},
	}

	// validate
	tps := []string{
		`sumologic.accessId = "su9OL59biWiJu7"`,      // gitleaks:allow
		`sumologic_access_id = "sug5XpdpaoxtOH"`,     // gitleaks:allow
		`export SUMOLOGIC_ACCESSID="suDbJw97o9WVo0"`, // gitleaks:allow
		`SUMO_ACCESS_ID = "suGyI5imvADdvU"`,          // gitleaks:allow
		generateSampleSecret("sumo", "su"+secrets.NewSecret(alphaNumeric("12"))),
	}
	fps := []string{
		`- (NSNumber *)sumOfProperty:(NSString *)property;`,
		`- (NSInteger)sumOfValuesInRange:(NSRange)range;`,
		`+ (unsigned char)byteChecksumOfData:(id)arg1;`,
		`sumOfExposures = sumOfExposures;`, // gitleaks:allow
		`.si-sumologic.si--color::before { color: #000099; }`,
		`/// Based on the SumoLogic keyword syntax:`,
		`sumologic_access_id         = ""`,
		`SUMOLOGIC_ACCESSID: ${SUMOLOGIC_ACCESSID}`,
		`export SUMOLOGIC_ACCESSID=XXXXXXXXXXXXXX`, // gitleaks:allow
	}
	return validate(r, tps, fps)
}

func SumoLogicAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sumologic-access-token",
		Description: "SumoLogic Access Token",
		Regex: generateSemiGenericRegex([]string{"sumo"},
			alphaNumeric("64"), true),
		SecretGroup: 1,
		Entropy:     3,
		Keywords: []string{
			"sumo",
		},
	}

	// validate
	tps := []string{
		`export SUMOLOGIC_ACCESSKEY="3HSa1hQfz6BYzlxf7Yb1WKG3Hyovm56LMFChV2y9LgkRipsXCujcLb5ej3oQUJlx"`, // gitleaks:allow
		`SUMO_ACCESS_KEY: gxq3rJQkS6qovOg9UY2Q70iH1jFZx0WBrrsiAYv4XHodogAwTKyLzvFK4neRN8Dk`,             // gitleaks:allow
		`SUMOLOGIC_ACCESSKEY: 9RITWb3I3kAnSyUolcVJq4gwM17JRnQK8ugRaixFfxkdSl8ys17ZtEL3LotESKB7`,         // gitleaks:allow
		`sumo_access_key = "3Kof2VffNQ0QgYIhXUPJosVlCaQKm2hfpWE6F1fT9YGY74blQBIPsrkCcf1TwKE5"`,          // gitleaks:allow
		generateSampleSecret("sumo", secrets.NewSecret(alphaNumeric("64"))),
	}
	fps := []string{
		`#   SUMO_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`, // gitleaks:allow
		"-e SUMO_ACCESS_KEY=`etcdctl get /sumologic_secret`",
		`SUMO_ACCESS_KEY={SumoAccessKey}`,
		`SUMO_ACCESS_KEY=${SUMO_ACCESS_KEY:=$2}`,
		`sumo_access_key   = "<SUMOLOGIC ACCESS KEY>"`,
		`SUMO_ACCESS_KEY: AbCeFG123`,
	}
	return validate(r, tps, fps)
}
