package rules

import (
	"fmt"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

// References:
// - https://learn.microsoft.com/en-us/microsoft-365/compliance/sit-defn-azure-ad-client-secret
// - https://learn.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app#add-credentials
func AzureActiveDirectoryClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "azure-ad-client-secret",
		Description: "Azure AD Client Secret",
		// After inspecting dozens of secrets, I'm fairly confident that they start with `xxx\dQ~`.
		// However, this may not be (entirely) true, and this rule might need to be further refined in the future.
		// Furthermore, it's possible that secrets have a checksum that could be used to further constrain this pattern.
		Regex:   regexp.MustCompile(`(?:^|[\\'"\x60\s>=:(,)])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\'"\x60\s<),])`), // wtf, Go? https://github.com/golang/go/issues/18221
		Entropy: 3,
		Keywords: []string{
			"Q~",
		},
	}

	// validate
	tps := []string{
		`client_secret=bP88Q~rcBcYjzzOhg1Hnn76Wm3jGgakZiZ.8vMgR`, // gitleaks:allow
		`client_secret=bP88Q~rcBcYjzzOhg1Hnn76Wm3jGgakZiZ.8vMgR
`, // gitleaks:allow
		`client_secret: .IQ8Q~79R7TOWOspFnWcEG-dYt4KXqFqxK16cxr`,                                                                                              // gitleaks:allow
		`AUTH_CLIENTSECRET = _V28Q~IC8qxmlWNpHuDm34JlbKv9LXV5MvUR3a-P`,                                                                                        // gitleaks:allow
		`<value xsi:type="xsd:string">~Gg8Q~nVhlLi2vpg_nXBGqFsbGK-t~Hus1JmTa0y</value>`,                                                                       // gitleaks:allow
		`"CLIENT_SECRET": "YYz7Q~Sudoqwap1PnzEBA3zqBK~i5uesDIv.C"`,                                                                                            // gitleaks:allow
		`Set-PSUAuthenticationMethod -Type 'OpenIDConnect' -CallbackPath '/auth/oidc' -ClientId 'fake' -ClientSecret '2Vq7Q~q5VgKljZ7cb3.0sp0Apz.vOjRIPyeTr'`, // gitleaks:allow
		`client-secret: "t028Q~-aLbmQuinnZtzbgtlEAYstnBWEmGPAoBm"`,                                                                                            // gitleaks:allow
		`"cas.authn.azure-active-directory.client-secret=qHF8Q~PCM5HhMoyTFc5TYEomnzR6Kim9UJhe8a.P",`,                                                          // gitleaks:allow
		`"line": "client_srt = \"qpF8Q~PCM5MhMoyTFc5TYEomnYRUKim9UJhe8a2P\";",`,                                                                               // gitleaks:allow
		`"client_secret":       acctest.Representation{RepType: acctest.Required, Create: 'dO29Q~F5-VwnW.lZdd11xFF_t5NAXCaGwDl9NbT1'},`,                       // gitleaks:allow
		`Example= GN.7Q~4AkLZBNEbz4Jxlm~O5G6SsyFxYg6zMR`,                                                                                                      // gitleaks:allow
		`"the_value": "QtT8Q~9C-_Ij~RouHVpD2Tuf3oHWGh.DQ3kcjbAn"`,                                                                                             // gitleaks:allow
		`QtT8Q~9C-_Ij~RouHVpD2Tuf3oHWGh.DQ3kcjbAn`,                                                                                                            // gitleaks:allow
		`(use the client secret: QtT8Q~9C-_Ij~RouHVpD2Tuf3oHWGh.DQ3kcjbAn)`,                                                                                   // gitleaks:allow
		`(QtT8Q~9C-_Ij~RouHVpD2Tuf3oHWGh.DQ3kcjbAn)`,                                                                                                          // gitleaks:allow
		`\"pass\": \"` + fmt.Sprintf("%s%sQ~%s", secrets.NewSecret(`[\w~.]{3}`), secrets.NewSecret(utils.Numeric("1")), secrets.NewSecret(`[\w~.-]{31,34}`)),
	}
	fps := []string{
		`![图源：《深入拆解Tomcat & Jetty》](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/6a9e704af49b4380bb686f0c96d33b81~tplv-k3u1fbpfcp-watermark.image)`,
		`~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`,
		`~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`,
		`.ui.visible.right.sidebar~.ui.visible.left.sidebar~.pusher{transform:translate3d(0,0,0)}`,
		`buf.WriteString("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n::\n\n")`,
		`'url': 'http://www.2doc.nl/speel~VARA_101375237~mh17-het-verdriet-van-nederland~.html',`,
		`@ar = split("~", "965f1453~47~09414c93e4cef985416f472549220827da3ba6fed8ad28e29ef6ad170ad53a69051e9b06f439ef6da5df8670181f7eb2481650");`,
		`'#!/registries/5/portainer.demo~2Fportainerregistrytesting~2Falpine',`,
		`// CloudFront-Signature: Ixn4bF1LLrLcB8XG-t5bZbIB0vfwSF2s4gkef~PcNBdx73MVvZD3v8DZ5GzcqNrybMiqdYJY5KqK6vTsf5JXDgwFFz-h98wdsbV-izcuonPdzMHp4Ay4qyXM6Ed5jB9dUWYGwMkA6rsWXpftfX8xmk4tG1LwFuJV6nAsx4cfpuKwo4vU2Hyr2-fkA7MZG8AHkpDdVUnjm1q-Re9HdG0nCq-2lnBAdOchBpJt37narOj-Zg6cbx~6rzQLVQd8XIv-Bn7VTc1tkBAJVtGOHb0Q~PLzSRmtNGYTnpL0z~gp3tq8lhZc2HuvJW5-tZaYP9yufeIzk5bqsT6DT4iDuclKKw__, , , false`,
		`+ "<Trust Comment=\"\" Identity=\"USK@u2vn3Lh6Kte2-TgBSNKorbsKkuAt34ckoLmgx0ndXO0,4~q8Q~3wIHjX9DT0yCNfQmr9oxmYrDZoQVLOdNg~yk0,AQACAAE/WebOfTrustRC2/2\" Value=\"100\"/>"`,
		`client_secret=bP88Q~xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
	}
	return utils.Validate(r, tps, fps)
}

// References:
// - https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate
// - https://docs.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/pats
func AzureDevOpsPAT() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "azure-devops-pat",
		Description: "Identified an Azure DevOps Personal Access Token, potentially compromising project management and development workflow security.",
		// Azure DevOps PATs are 52-character base64-encoded strings  
		Regex:   utils.GenerateSemiGenericRegex([]string{"devops", "ado", "vsts", "visualstudio", "dev.azure", "azure_devops"}, utils.AlphaNumeric("52"), true),
		Entropy: 3.5,
		Keywords: []string{
			"devops",
			"ado",
			"vsts",
			"visualstudio",
			"dev.azure",
			"azure_devops",
		},
	}

	// validate
	tps := []string{
		`devops_token=` + secrets.NewSecret(utils.AlphaNumeric("52")), // gitleaks:allow
		`ado_pat: ` + secrets.NewSecret(utils.AlphaNumeric("52")),     // gitleaks:allow
		`VSTS_TOKEN="` + secrets.NewSecret(utils.AlphaNumeric("52")) + `"`, // gitleaks:allow
	}
	fps := []string{
		`xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`, // low entropy
		`ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOP`, // all uppercase, wrong length
		`very_long_variable_name_that_might_look_like_a_token_but_isnt`, // too long
		`short_token=abc123`, // too short
	}
	return utils.Validate(r, tps, fps)
}

// References:
// - https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage
// - https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key
func AzureStorageAccountKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "azure-storage-account-key",
		Description: "Found an Azure Storage Account Key, risking unauthorized access to cloud storage and data breaches.",
		// Azure Storage Account Keys are 88-character base64 strings ending with ==
		Regex:   utils.GenerateSemiGenericRegex([]string{"accountkey", "account_key", "storagekey", "storage_key", "azure", "storage"}, `[A-Za-z0-9+/]{84}==`, true),
		Entropy: 4,
		Keywords: []string{
			"accountkey",
			"account_key",
			"storagekey",
			"storage_key",
			"azure",
			"storage",
		},
	}

	// validate
	tps := []string{
		`accountkey=` + secrets.NewSecret(`[A-Za-z0-9+/]{84}`) + `==`, // gitleaks:allow
		`storage_key: "` + secrets.NewSecret(`[A-Za-z0-9+/]{84}`) + `=="`, // gitleaks:allow
		`azure_storage_key=` + secrets.NewSecret(`[A-Za-z0-9+/]{84}`) + `==`, // gitleaks:allow
	}
	fps := []string{
		`AccountKey=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx==`, // low entropy
		`storage_key="YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY=="`, // low entropy
		`key=abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdef==`, // too long
		`short_key=abc123==`, // too short
		`AccountKey=NotActuallyBase64Characters!@#$%^&*()+=`,                                             // invalid base64
	}
	return utils.Validate(r, tps, fps)
}

// References:
// - https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview
// - https://docs.microsoft.com/en-us/rest/api/storageservices/create-service-sas
func AzureSASToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "azure-sas-token",
		Description: "Discovered an Azure SAS Token, potentially allowing unauthorized access to Azure Storage resources and data exposure.",
		// Azure SAS tokens contain signature (sig), expiry (se), resource (sr), and permissions (sp) parameters
		Regex:   regexp.MustCompile(`(\?|\&)(sv|ss|srt|sp|st|se|sip|spr|sig)=[^&\s]+(&(sv|ss|srt|sp|st|se|sip|spr|sig)=[^&\s]+){3,}`),
		Entropy: 3,
		Keywords: []string{
			"sig=",
			"se=",
			"sr=",
			"sp=",
			"sas",
			"blob.core.windows.net",
			"table.core.windows.net",
			"queue.core.windows.net",
			"file.core.windows.net",
		},
	}

	// validate
	tps := []string{
		`https://myaccount.blob.core.windows.net/mycontainer?sv=2020-08-04&ss=bfqt&srt=sco&sp=rwdlacupx&se=2021-12-31T23:59:59Z&st=2021-01-01T00:00:00Z&spr=https&sig=` + secrets.NewSecret(utils.AlphaNumeric("44")), // gitleaks:allow
		`SAS_TOKEN="?sv=2020-08-04&ss=b&srt=o&sp=r&se=2021-12-31T23:59:59Z&sig=` + secrets.NewSecret(utils.AlphaNumeric("44")) + `"`,                                                                                   // gitleaks:allow
		`azure_sas_url = "https://storage.blob.core.windows.net/container?sv=2020-08-04&sr=c&sp=rl&se=2021-12-31T23:59:59Z&sig=` + secrets.NewSecret(utils.AlphaNumeric("44")) + `"`,                               // gitleaks:allow
		`?sv=2020-08-04&ss=bfqt&srt=sco&sp=rwdlacupx&se=2021-12-31T23:59:59Z&sig=` + secrets.NewSecret(utils.AlphaNumeric("44")),                                                                                     // gitleaks:allow
		`&sv=2020-08-04&sr=b&sp=r&se=2021-12-31T23:59:59Z&st=2021-01-01T00:00:00Z&sig=` + secrets.NewSecret(utils.AlphaNumeric("44")),                                                                               // gitleaks:allow
	}
	fps := []string{
		`https://example.com?param1=value1&param2=value2&param3=value3`, // not SAS-specific parameters
		`?sv=2020-08-04&se=2021-12-31T23:59:59Z`,                       // too few parameters
		`?normal=query&string=parameters&not=sas`,                       // not SAS parameters
		`sig=shortstring`,                                               // too short signature
		`https://example.com?regular=url&with=normal&params=here`,       // regular URL parameters
	}
	return utils.Validate(r, tps, fps)
}