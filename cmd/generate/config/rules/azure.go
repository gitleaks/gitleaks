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
// - https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage
// - https://learn.microsoft.com/en-us/azure/storage/common/storage-configure-connection-string
//
// Azure Storage connection strings begin with `DefaultEndpointsProtocol=`,
// a literal that is unique enough to anchor on without an external identifier.
// The embedded account key is 64 bytes encoded as 88 base64 characters that
// always end in `==`.
func AzureStorageConnectionString() *config.Rule {
	r := config.Rule{
		RuleID:      "azure-storage-connection-string",
		Description: "Identified an Azure Storage account connection string, which embeds a 64-byte account key granting full access to the storage account.",
		Regex: regexp.MustCompile(
			`(?i)DefaultEndpointsProtocol=https?;` +
				`(?:[A-Za-z]+=[^;\s"'<>]{1,128};){0,5}` +
				`AccountKey=([A-Za-z0-9+/]{86}==)`,
		),
		SecretGroup: 1,
		Entropy:     3,
		Keywords:    []string{"defaultendpointsprotocol"},
	}

	// validate
	tps := []string{
		`AZURE_STORAGE_CONNECTION_STRING="DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=` + secrets.NewSecret(`[A-Za-z0-9+/]{86}`) + `==;EndpointSuffix=core.windows.net"`,
		`conn = "DefaultEndpointsProtocol=https;AccountName=examplestg01;AccountKey=` + secrets.NewSecret(`[A-Za-z0-9+/]{86}`) + `=="`,
		`AZURE_WEBJOBS_STORAGE = DefaultEndpointsProtocol=https;AccountName=funcsa;AccountKey=` + secrets.NewSecret(`[A-Za-z0-9+/]{86}`) + `==;EndpointSuffix=core.windows.net`,
		// AccountKey appearing first after the protocol.
		`DefaultEndpointsProtocol=https;AccountKey=` + secrets.NewSecret(`[A-Za-z0-9+/]{86}`) + `==;AccountName=funcsa`,
		// HTTP (not HTTPS) variant -- still valid syntax.
		`DefaultEndpointsProtocol=http;AccountName=local;AccountKey=` + secrets.NewSecret(`[A-Za-z0-9+/]{86}`) + `==;BlobEndpoint=http://127.0.0.1:10000/local`,
	}
	fps := []string{
		// Documentation placeholder.
		`DefaultEndpointsProtocol=https;AccountName=<account>;AccountKey=<your-account-key>;EndpointSuffix=core.windows.net`,
		// Wrong length on the key.
		`DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=ABC123==`,
		// Low-entropy (all-A) key.
		`DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==`,
		// Connection string mentioned without an AccountKey field.
		`DefaultEndpointsProtocol=https;AccountName=mystorageaccount;EndpointSuffix=core.windows.net`,
		// Single-padding (87+1) is not a 64-byte key.
		`DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=` + secrets.NewSecret(`[A-Za-z0-9+/]{87}`) + `=`,
		// Common ${...} templating placeholder.
		`DefaultEndpointsProtocol=https;AccountName=${STORAGE_NAME};AccountKey=${STORAGE_KEY};EndpointSuffix=core.windows.net`,
	}
	return utils.Validate(r, tps, fps)
}
