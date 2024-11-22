package rules

import (
	"fmt"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func EtsyAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "etsy-access-token",
		Description: "Found an Etsy Access Token, potentially compromising Etsy shop management and customer data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"(?-i:ETSY|[Ee]tsy)"}, utils.AlphaNumeric("24"), true),
		Entropy:     3,
		Keywords: []string{
			"etsy",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("ETSY", secrets.NewSecret(utils.AlphaNumeric("24")))
	tps = append(tps, utils.GenerateSampleSecrets("etsy", secrets.NewSecret(utils.AlphaNumeric("24")))...)
	tps = append(tps, utils.GenerateSampleSecrets("Etsy", secrets.NewSecret(utils.AlphaNumeric("24")))...)
	fps := []string{
		fmt.Sprintf(`SetSysctl = "%s"`, secrets.NewSecret(utils.AlphaNumeric("24"))),
		`	if err := sysctl.SetSysctl(sysctlBridgeCallIPTables); err != nil {`,
		`g6Rib2R5hqhkZXRhY2hlZMOpaGFzaF90eXBlCqNrZXnEIwEgETSYcPQGcaAxl8vuQDLahSfhxkEEHu2flbF9ErAooEoKp3BheWxvYWTFAwB7ImJvZHkiOnsia2V5Ijp7ImVsZGVzdF9raWQiOiIwMTIwMTEzNDk4NzBmNDA2NzFhMDMxOTdjYmVlNDAzMmRhODUyN2UxYzY0MTA0MWVlZDlmOTViMTdkMTJiMDI4YTA0YTBhIiwiaG9zdCI6ImtleWJhc2UuaW8iLCJraWQiOiIwMTIwMTEzNDk4NzBmNDA2NzFhMDMxOTdjYmVlNDAzMmRhODUyN2UxYzY0MTA0MWVlZDlmOTViMTdkMTJiMDI4YTA0YTBhIiwidWlkIjoiYzUyZjc2M2MxNzYyNWZiMTI5YWU1ZDZmZThhMGUzMTkiLCJ1c2VybmFtZSI6ImttYXJla3NwYXJ0eiJ9LCJzZXJ2aWNlIjp7Imhvc3RuYW1lIjoia3lsZS5tYXJlay1zcGFydHoub3JnIiwicHJvdG9jb2wiOiJodHRwOiJ9LCJ0eXBlIjoid2ViX3NlcnZpY2VfYmluZGluZyIsInZlcnNpb24iOjF9LCJjbGllbnQiOnsibmFtZSI6ImtleWJhc2UuaW8gZ28gY2xpZW50IiwidmVyc2lvbiI6IjEuMC4xNCJ9LCJjdGltZSI6MTQ1ODU5MDYyMSwiZXhwaXJlX2luIjo1MDQ1NzYwMDAsIm1lcmtsZV9yb290Ijp7ImN0aW1lIjoxNDU4NTkwNTgzLCJoYXNoIjoiODQ0ZWRkNGU0OTQ3MWUzNWQxZTFkOTM5YTc0ZjUwMDc5Nzg3NzljMTAwYzY1NGE2OGI1NDNhYzY2Y2NlYTQ1MGFjNTllNmY3Yjc4ZGZiN2MyYzdjMmYwMzJiYTA2MzdjMzVjZDk1ZGYyZmRiNjFlNjgxMjVmNDkxNjVlZDkwNzMiLCJzZXFubyI6NDE3Mjk5fSwicHJldiI6IjdmNWFkMGZlZmQxNjM4ZjBlOTc1MTk3NzA5YTk2OTVkZmQ1NzU0MTA4NTYxZGUzMDM0ODc2NDcxODdhMDkyYzUiLCJzZXFubyI6OSwidGFnIjoic2lnbmF0dXJlIn2jc2lnxEDDVCB/SdOzo+BznIUCCa5DgISbH+0noUjyAJ4r0sH/tj8lYNpHw3WR93SBCufeElsl7KrxVdg5qU5ADYj26wgOqHNpZ190eXBlIKN0YWfNAgKndmVyc2lvbgE=`,
		`in XCBuild.XCBBuildServiceSession.setSystemInfo(operatingSystemVersion: __C.NSOperatingSystemVersion, productBuildVersion: Swift.String, nativeArchitecture: Swift.String, completion: (Swift.Bool) -> ()) -> ()`,
	}
	return utils.Validate(r, tps, fps)
}
