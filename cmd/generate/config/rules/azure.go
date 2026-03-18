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
func AzureStorageAccountKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "azure-storage-account-key",
		Description: "Detected an Azure Storage Account Key, which may compromise cloud storage access and lead to data breaches or unauthorized data manipulation.",
		// Storage account keys are 88-character base64 strings ending in "=="
		// The identifier keywords use underscore variants to match generated sample secrets.
		Regex:   utils.GenerateSemiGenericRegex([]string{"account.?key", "storage.?key", "accountkey", "storagekey", "azure.?storage"}, `[A-Za-z0-9+/]{86}==`, true),
		Entropy: 4.5,
		Keywords: []string{
			// keywords are Aho-Corasick pre-filter substrings; include both separator variants
			"accountkey", "account_key", "account-key",
			"storagekey", "storage_key", "storage-key",
		},
	}

	// validate
	// GenerateSampleSecrets("accountKey", ...) produces strings with "accountKey" (camelCase) which
	// lowercases to "accountkey" — matching the keyword.
	tps := utils.GenerateSampleSecrets("accountKey", secrets.NewSecret(`[A-Za-z0-9+/]{86}==`))
	tps = append(tps, utils.GenerateSampleSecrets("storageKey", secrets.NewSecret(`[A-Za-z0-9+/]{86}==`))...)
	fps := []string{
		// too short — only 64 base64 chars (not 88)
		`accountKey = "dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleXRlc3RrZXk="`,
	}
	return utils.Validate(r, tps, fps)
}

// References:
// - https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-sas
func AzureServiceBusConnectionString() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "azure-service-bus-connection-string",
		Description: "Identified an Azure Service Bus Connection String, risking unauthorized access to message queues and potential data interception or service disruption.",
		Regex:       regexp.MustCompile(`Endpoint=sb://[^;]+\.servicebus\.windows\.net[^;]*;SharedAccessKey(?:Name)?=[^;]*;SharedAccessKey=[A-Za-z0-9+/=]{43,44}(?:[^A-Za-z0-9+/=]|$)`),
		Entropy:     3.5,
		Keywords: []string{
			"servicebus.windows.net",
		},
	}

	// validate
	tps := []string{
		`connectionString = "Endpoint=sb://mynamespace.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=` + secrets.NewSecret(`[A-Za-z0-9+/]{43}=`) + `"`, // gitleaks:allow
		`SB_CONN="Endpoint=sb://prod-bus.servicebus.windows.net/;SharedAccessKeyName=policy1;SharedAccessKey=` + secrets.NewSecret(`[A-Za-z0-9+/]{43}=`) + `"`,                                 // gitleaks:allow
	}
	fps := []string{
		`Endpoint=sb://mynamespace.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=<your-key-here>`,
		`Endpoint=sb://mynamespace.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
	}
	return utils.Validate(r, tps, fps)
}

// References:
// - https://learn.microsoft.com/en-us/azure/cosmos-db/nosql/security/how-to-grant-data-plane-access
func AzureCosmosDBConnectionString() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "azure-cosmos-db-connection-string",
		Description: "Discovered an Azure Cosmos DB Connection String with an account key, potentially compromising database access and leading to data exposure or manipulation.",
		Regex:       regexp.MustCompile(`AccountEndpoint=https://[^;]+\.documents\.azure\.com[^;]*;AccountKey=[A-Za-z0-9+/]{86}==`),
		Entropy:     3.5,
		Keywords: []string{
			"documents.azure.com",
		},
	}

	// validate
	tps := []string{
		`COSMOS_CONN="AccountEndpoint=https://myaccount.documents.azure.com:443/;AccountKey=` + secrets.NewSecret(`[A-Za-z0-9+/]{86}==`) + `"`, // gitleaks:allow
	}
	fps := []string{
		`AccountEndpoint=https://myaccount.documents.azure.com:443/;AccountKey=<your-key>`,
		`AccountEndpoint=https://myaccount.documents.azure.com:443/;AccountKey=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
	}
	return utils.Validate(r, tps, fps)
}

// References:
// - https://learn.microsoft.com/en-us/azure/azure-sql/database/connect-query-content-reference-guide
func AzureSQLConnectionString() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "azure-sql-connection-string",
		Description: "Found an Azure SQL Connection String containing a password, risking unauthorized database access and potential data breaches.",
		Regex:       regexp.MustCompile(`(?i)(?:Server|Data Source)=(?:tcp:)?[\w.-]+\.database\.windows\.net[^;]*;(?:[^;]*;)*Password=([^;'"` + "`" + `\s]{8,})`),
		Entropy:     3,
		Keywords: []string{
			"database.windows.net",
		},
	}

	// validate
	tps := []string{
		`connectionString = "Server=tcp:myserver.database.windows.net,1433;Database=mydb;User ID=admin;Password=` + secrets.NewSecret(`[A-Za-z0-9!@#$%^&]{16}`) + `;Encrypt=True"`, // gitleaks:allow
		`Data Source=myserver.database.windows.net;Initial Catalog=mydb;User ID=sa;Password=` + secrets.NewSecret(`[A-Za-z0-9!@#$%^&]{20}`),                                        // gitleaks:allow
	}
	fps := []string{
		// env var placeholder — global allowlist catches $VAR patterns but we keep this explicit
		`Server=tcp:myserver.database.windows.net,1433;Database=mydb;User ID=admin;Password=${DB_PASSWORD}`,
	}
	return utils.Validate(r, tps, fps)
}

// References:
// - https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate
func AzureDevOpsPAT() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "azure-devops-personal-access-token",
		Description: "Uncovered an Azure DevOps Personal Access Token, which could allow unauthorized access to Azure DevOps services, repositories, and pipelines.",
		// Azure DevOps PATs are base64-encoded and typically 52 characters long.
		// We scope to identifiers that contain "azdo" or "azure_devops" / "azure-devops" to reduce
		// false positives — any 52-char alphanumeric string is very common.
		Regex:   utils.GenerateSemiGenericRegex([]string{"azdo", "azure.?devops"}, `[A-Za-z0-9]{52}`, true),
		Entropy: 4.5,
		Keywords: []string{
			// pre-filter substrings: must literally appear in scanned content
			"azdo", "azure_devops", "azure-devops",
		},
	}

	// validate — use identifiers whose lowercased form contains a keyword substring
	tps := utils.GenerateSampleSecrets("azdo_token", secrets.NewSecret(`[A-Za-z0-9]{52}`))
	tps = append(tps,
		// bare assignment forms that don't go through GenerateSampleSecrets template
		`AZDO_TOKEN = "`+secrets.NewSecret(`[A-Za-z0-9]{52}`)+`"`,       // gitleaks:allow
		`azure_devops_pat = "`+secrets.NewSecret(`[A-Za-z0-9]{52}`)+`"`, // gitleaks:allow
		`azure-devops-pat: `+secrets.NewSecret(`[A-Za-z0-9]{52}`),       // gitleaks:allow
	)
	fps := []string{
		`azdo_token = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`,
	}
	return utils.Validate(r, tps, fps)
}

// References:
// - https://learn.microsoft.com/en-us/azure/container-registry/container-registry-authentication
func AzureContainerRegistryPassword() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "azure-container-registry-password",
		Description: "Detected an Azure Container Registry password or admin credential, potentially allowing unauthorized access to container images.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"acr.?password", "registry.?password", "container.?registry"}, `[A-Za-z0-9+/=]{32,44}`, true),
		Entropy:     4,
		Keywords: []string{
			"acr_password", "acr-password", "registry_password", "registry-password",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("acr_password", secrets.NewSecret(`[A-Za-z0-9+/]{43}=`))
	tps = append(tps, utils.GenerateSampleSecrets("registry_password", secrets.NewSecret(`[A-Za-z0-9+/]{32}`))...)
	fps := []string{
		`acr_password = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`,
	}
	return utils.Validate(r, tps, fps)
}

// References:
// - https://learn.microsoft.com/en-us/azure/azure-functions/functions-how-to-use-azure-function-app-settings
// - https://learn.microsoft.com/en-us/azure/api-management/api-management-subscriptions
func AzureFunctionKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "azure-function-key",
		Description: "Found an Azure Function Key, which could allow unauthorized invocation of Azure Functions and exposure of serverless application logic.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"function.?key", "azure.?function", "x-functions-key"}, `[A-Za-z0-9_\-]{40,80}(?:[=]{0,2})`, true),
		Entropy:     4,
		Keywords: []string{
			"function_key", "function-key", "azure_function", "azure-function", "x-functions-key",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("function_key", secrets.NewSecret(`[A-Za-z0-9_\-]{54}==`))
	tps = append(tps, utils.GenerateSampleSecrets("azure_function_key", secrets.NewSecret(`[A-Za-z0-9_\-]{40}`))...)
	fps := []string{
		`function_key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`,
	}
	return utils.Validate(r, tps, fps)
}

// References:
// - https://learn.microsoft.com/en-us/azure/azure-app-configuration/concept-enable-rbac
func AzureAppConfigConnectionString() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "azure-app-configuration-connection-string",
		Description: "Identified an Azure App Configuration Connection String, risking unauthorized access to application configuration data.",
		Regex:       regexp.MustCompile(`Endpoint=https://[^;]+\.azconfig\.io;Id=[A-Za-z0-9+/\-]{14,22};Secret=[A-Za-z0-9+/]{43}=`),
		Entropy:     3.5,
		Keywords: []string{
			"azconfig.io",
		},
	}

	// validate
	tps := []string{
		`APP_CONFIG="Endpoint=https://myconfig.azconfig.io;Id=` + secrets.NewSecret(`[A-Za-z0-9+/\-]{20}`) + `;Secret=` + secrets.NewSecret(`[A-Za-z0-9+/]{43}=`) + `"`, // gitleaks:allow
	}
	fps := []string{
		`Endpoint=https://myconfig.azconfig.io;Id=<access-key-id>;Secret=<access-key-secret>`,
		`Endpoint=https://myconfig.azconfig.io;Id=xxxxxxxxxxxxxxxxxxxx;Secret=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
	}
	return utils.Validate(r, tps, fps)
}

// References:
// - https://learn.microsoft.com/en-us/azure/azure-signalr/signalr-overview
func AzureSignalRConnectionString() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "azure-signalr-connection-string",
		Description: "Detected an Azure SignalR Service Connection String, potentially exposing real-time messaging infrastructure credentials.",
		Regex:       regexp.MustCompile(`Endpoint=https://[^;]+\.service\.signalr\.net;AccessKey=[A-Za-z0-9+/]{43}=`),
		Entropy:     3.5,
		Keywords: []string{
			"service.signalr.net",
		},
	}

	// validate
	tps := []string{
		`SIGNALR_CONN="Endpoint=https://myhub.service.signalr.net;AccessKey=` + secrets.NewSecret(`[A-Za-z0-9+/]{43}=`) + `;Version=1.0;"`, // gitleaks:allow
	}
	fps := []string{
		`Endpoint=https://myhub.service.signalr.net;AccessKey=<your-access-key>`,
		`Endpoint=https://myhub.service.signalr.net;AccessKey=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
	}
	return utils.Validate(r, tps, fps)
}

// References:
// - https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-get-connection-string
func AzureEventHubConnectionString() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "azure-event-hub-connection-string",
		Description: "Found an Azure Event Hub Connection String, which could allow unauthorized access to event streaming infrastructure.",
		Regex:       regexp.MustCompile(`Endpoint=sb://[^;]+\.servicebus\.windows\.net[^;]*;SharedAccessKeyName=[^;]+;SharedAccessKey=[A-Za-z0-9+/]{43}=(?:;EntityPath=[^'"` + "`" + `\s]+)?`),
		Entropy:     3.5,
		Keywords: []string{
			"servicebus.windows.net", "entitypath",
		},
	}

	// validate
	tps := []string{
		`EH_CONN="Endpoint=sb://mynamespace.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=` + secrets.NewSecret(`[A-Za-z0-9+/]{43}=`) + `;EntityPath=myeventhub"`, // gitleaks:allow
	}
	fps := []string{
		`Endpoint=sb://mynamespace.servicebus.windows.net/;SharedAccessKeyName=policy;SharedAccessKey=<your-key>;EntityPath=myeventhub`,
		`Endpoint=sb://mynamespace.servicebus.windows.net/;SharedAccessKeyName=policy;SharedAccessKey=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;EntityPath=hub`,
	}
	return utils.Validate(r, tps, fps)
}

// References:
// - https://learn.microsoft.com/en-us/azure/iot-hub/iot-hub-dev-guide-sas
func AzureIoTHubConnectionString() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "azure-iot-hub-connection-string",
		Description: "Identified an Azure IoT Hub Connection String, risking unauthorized access to IoT device management and data streams.",
		Regex:       regexp.MustCompile(`HostName=[^;]+\.azure-devices\.net;SharedAccessKeyName=[^;]+;SharedAccessKey=[A-Za-z0-9+/]{43}=`),
		Entropy:     3.5,
		Keywords: []string{
			"azure-devices.net",
		},
	}

	// validate
	tps := []string{
		`IOT_CONN="HostName=myhub.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=` + secrets.NewSecret(`[A-Za-z0-9+/]{43}=`) + `"`, // gitleaks:allow
	}
	fps := []string{
		`HostName=myhub.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=<your-key>`,
		`HostName=myhub.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
	}
	return utils.Validate(r, tps, fps)
}

// References:
// - https://learn.microsoft.com/en-us/azure/batch/batch-account-create-portal
func AzureBatchAccountKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "azure-batch-account-key",
		Description: "Detected an Azure Batch Account Key, potentially allowing unauthorized access to batch computing resources.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"batch.?key", "batch.?account.?key", "azure.?batch"}, `[A-Za-z0-9+/]{88}`, true),
		Entropy:     4.5,
		Keywords: []string{
			"batch_key", "batch-key", "azure_batch", "azure-batch",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("batch_key", secrets.NewSecret(`[A-Za-z0-9+/]{88}`))
	tps = append(tps, utils.GenerateSampleSecrets("azure_batch_key", secrets.NewSecret(`[A-Za-z0-9+/]{88}`))...)
	fps := []string{
		`batch_key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`,
	}
	return utils.Validate(r, tps, fps)
}

// References:
// - https://learn.microsoft.com/en-us/azure/search/search-security-api-keys
func AzureSearchAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "azure-search-api-key",
		Description: "Found an Azure Cognitive Search API Key, which may allow unauthorized read or write access to search indexes and data.",
		// Azure Search admin keys are 32 hex characters.
		// Hex strings (16-char alphabet) have a theoretical max entropy of 4.0;
		// random 32-char hex averages ~3.3-3.5, so we use a lower threshold.
		Regex:   utils.GenerateSemiGenericRegex([]string{"search.?key", "search.?api.?key", "azure.?search", "cognitive.?search"}, `[A-Fa-f0-9]{32}`, true),
		Entropy: 3,
		Keywords: []string{
			"search_key", "search-key", "azure_search", "azure-search",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("search_key", secrets.NewSecret(`[a-f0-9]{32}`))
	tps = append(tps, utils.GenerateSampleSecrets("azure_search_api_key", secrets.NewSecret(`[a-f0-9]{32}`))...)
	fps := []string{
		`search_key = "00000000000000000000000000000000"`,
		`azure_search_key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`,
	}
	return utils.Validate(r, tps, fps)
}

// References:
// - https://learn.microsoft.com/en-us/azure/azure-maps/azure-maps-authentication
func AzureMapsSubscriptionKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "azure-maps-subscription-key",
		Description: "Discovered an Azure Maps Subscription Key, potentially exposing geospatial services and location data APIs.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"maps.?key", "maps.?subscription", "azure.?maps"}, `[A-Za-z0-9\-_]{40,50}`, true),
		Entropy:     4,
		Keywords: []string{
			"maps_key", "maps-key", "azure_maps", "azure-maps",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("maps_key", secrets.NewSecret(`[A-Za-z0-9\-_]{43}`))
	tps = append(tps, utils.GenerateSampleSecrets("azure_maps_subscription_key", secrets.NewSecret(`[A-Za-z0-9\-_]{40}`))...)
	fps := []string{
		`maps_key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`,
	}
	return utils.Validate(r, tps, fps)
}
