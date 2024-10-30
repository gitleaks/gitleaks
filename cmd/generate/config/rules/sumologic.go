package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func SumoLogicAccessID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sumologic-access-id",
		Description: "Discovered a SumoLogic Access ID, potentially compromising log management services and data analytics integrity.",
		// TODO: Make 'su' case-sensitive.
		Regex:   utils.GenerateSemiGenericRegex([]string{"(?-i:[Ss]umo|SUMO)"}, "su[a-zA-Z0-9]{12}", false),
		Entropy: 3,
		Keywords: []string{
			"sumo",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("sumo", secrets.NewSecret(`su[a-zA-Z0-9]{12}`))
	tps = append(tps,
		`sumologic.accessId = "su9OL59biWiJu7"`,      // gitleaks:allow
		`sumologic_access_id = "sug5XpdpaoxtOH"`,     // gitleaks:allow
		`export SUMOLOGIC_ACCESSID="suDbJw97o9WVo0"`, // gitleaks:allow
		`SUMO_ACCESS_ID = "suGyI5imvADdvU"`,          // gitleaks:allow
	)
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
		`sumObj = suGyI5imvADdvU`,
	}
	return utils.Validate(r, tps, fps)
}

func SumoLogicAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sumologic-access-token",
		Description: "Uncovered a SumoLogic Access Token, which could lead to unauthorized access to log data and analytics insights.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"(?-i:[Ss]umo|SUMO)"}, utils.AlphaNumeric("64"), true),
		Entropy:     3,
		Keywords: []string{
			"sumo",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("sumo", secrets.NewSecret(utils.AlphaNumeric("64")))
	tps = append(tps,
		`export SUMOLOGIC_ACCESSKEY="3HSa1hQfz6BYzlxf7Yb1WKG3Hyovm56LMFChV2y9LgkRipsXCujcLb5ej3oQUJlx"`, // gitleaks:allow
		`SUMO_ACCESS_KEY: gxq3rJQkS6qovOg9UY2Q70iH1jFZx0WBrrsiAYv4XHodogAwTKyLzvFK4neRN8Dk`,             // gitleaks:allow
		`SUMOLOGIC_ACCESSKEY: 9RITWb3I3kAnSyUolcVJq4gwM17JRnQK8ugRaixFfxkdSl8ys17ZtEL3LotESKB7`,         // gitleaks:allow
		`sumo_access_key = "3Kof2VffNQ0QgYIhXUPJosVlCaQKm2hfpWE6F1fT9YGY74blQBIPsrkCcf1TwKE5"`,          // gitleaks:allow
	)
	fps := []string{
		`#   SUMO_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`, // gitleaks:allow
		"-e SUMO_ACCESS_KEY=`etcdctl get /sumologic_secret`",
		`SUMO_ACCESS_KEY={SumoAccessKey}`,
		`SUMO_ACCESS_KEY=${SUMO_ACCESS_KEY:=$2}`,
		`sumo_access_key   = "<SUMOLOGIC ACCESS KEY>"`,
		`SUMO_ACCESS_KEY: AbCeFG123`,
		`sumOfExposures = 3Kof2VffNQ0QgYIhXUPJosVlCaQKm2hfpWE6F1fT9YGY74blQBIPsrkCcf1TwKE5;`,
	}
	return utils.Validate(r, tps, fps)
}
