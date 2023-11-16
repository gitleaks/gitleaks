package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// Rules come from https://www.powershellgallery.com/packages/AzSK.AzureDevOps/0.9.8/Content/Framework%5CConfigurations%5CSVT%5CAzureDevOps%5CCredentialPatterns.xml
// Only rules with 'ContentSearchPatterns' have been used.

// CSCAN0110, CSCAN0111, CSCAN0140, CSCAN0220 searches for generic passwords - covered elsewhere

// CSCAN0120 searches for Twilio keys - covered in twilio.go

// CSCAN0210 checks for Git repo credentials - covered elsewhere

// CSCAN0230 checks for Slack tokens - covered in slack.go

// CSCAN0250 - covered in jwt.go

func AzureAppServiceDeploymentSecrets() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0020, CSCAN0030 - Found Azure app service deployment secrets in publish settings file.",
		RuleID:      "azure-app-service-deployment-secrets",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`MII[a-z0-9=_\-]{200}`),
		Keywords:    []string{"MII"},
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-app-service-deployment-secrets",
			"MII"+secrets.NewSecret(alphaNumeric("200"))),
	}
	return validate(r, tps, nil)
}

func AzureStorageCredential86char() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0030, CSCAN0090, CSCAN0150 - Found Azure storage credential in source code file.",
		RuleID:      "azure-storage-credential-86char",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`[ \t]{0,10}[a-zA-Z0-9/+]{86}==`),
		Keywords:    []string{"=="},
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-storage-credential-86char",
			secrets.NewSecret(alphaNumeric("86")+"==")),
	}
	return validate(r, tps, nil)
}

func AzureStorageCredential43char() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0030, CSCAN0090, CSCAN0150 - Found Azure storage credential in source code file.",
		RuleID:      "azure-storage-credential-43char",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`[a-zA-Z0-9/+]{43}=[^{@\d%]`),
		Keywords:    []string{"="},
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-storage-credential-43char",
			secrets.NewSecret(alphaNumeric("43")+"=a")),
	}
	return validate(r, tps, nil)
}

func AzureStorageCredentialSig53() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0030, CSCAN0090, CSCAN0150 - Found Azure storage credential in source code file.",
		RuleID:      "azure-storage-credential-sig53",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`((sig|sas|password)=|>)[a-zA-Z0-9%]{43,53}%3d[^{a-zA-Z0-9%]`),
		Keywords:    []string{"sig", "sas", "password"},
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-storage-credential-sig53",
			"sig="+secrets.NewSecret(alphaNumeric("53")+"%3D")),
	}
	return validate(r, tps, nil)
}

func AzureStorageCredentialUserIDPW() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0030 - Found Azure storage credential in source code file.",
		RuleID:      "azure-storage-credential-useridpw",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`((user) ?(id|name)|uid)=.{2,128}?\s*?;\s*?((password)|(pwd))=[^'$%>@'";\[\{][^;"']{2,350}?(;|"|')`),
		Keywords:    []string{"userid=", ";password="},
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-storage-credential-useridpw",
			"userid="+secrets.NewSecret(alphaNumeric("128"))+";password="+secrets.NewSecret(alphaNumeric("200"))+";"),
	}
	return validate(r, tps, nil)
}

func AzureStorageCredentialAccountKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0030 - Found Azure storage credential in source code file.",
		RuleID:      "azure-storage-credential-accountkey",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`AccountKey\s*=\s*MII[a-zA-Z0-9/+]{43,}?={0,2}`),
		Keywords:    []string{"AccountKey = MII"},
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-storage-credential-accountkey",
			"AccountKey = MII"+secrets.NewSecret(alphaNumeric("43")+"=")),
	}
	return validate(r, tps, nil)
}

func AzureStorageCredentialXStore() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0100 - Found Azure storage credential in source code file.",
		RuleID:      "azure-storage-credential-xstore",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`<XstoreAccountInfo[ -~"\s\S\n\r\t]+accountSharedKey\s*=\s*"[^"]{30}[ -~"\s\S\n\r\t]+/>`),
		Keywords:    []string{"XstoreAccountInfo", "accountSharedKey"},
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-storage-credential-xstore",
			"<XstoreAccountInfo accountName = 'John Doe' accountSharedKey='"+secrets.NewSecret(alphaNumeric("43"))+"' />"),
	}
	return validate(r, tps, nil)
}

func AzureStorageCredentialServiceBus() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0100 - Found Azure storage credential in source code file.",
		RuleID:      "azure-storage-credential-servicebus",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`[<ServiceBusAccountInfo].*SharedAccessKey\s*=\s*[a-zA-Z0-9/+]{10,}['"]`),
		Keywords:    []string{"ServiceBusAccountInfo", "SharedAccessKey"},
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-storage-credential-servicebus",
			"<ServiceBusAccountInfo accountName='name' connectionString='Endpoint=sb://foo.net/;SharedAccessKeyName=bar;SharedAccessKey="+secrets.NewSecret(alphaNumeric("43"))+"' />"),
	}
	return validate(r, tps, nil)
}

func AzureStorageCredentialMonikerKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0130 - Found Azure storage credential in MonitoringAgent config file.",
		RuleID:      "azure-storage-credential-monikerkey",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`Account Moniker\s?=.*key\s?=.*`),
		Keywords:    []string{"Account Moniker"},
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-storage-credential-monikerkey",
			"Account Moniker = 'John Doe' Key = '"+secrets.NewSecret(alphaNumeric("200")+"'")),
	}
	return validate(r, tps, nil)
}

func AzureStorageCredentialBlobURL() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0110 - Found Azure storage credential in source code file.",
		RuleID:      "azure-storage-credential-bloburl",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`(?i)https://[a-zA-Z0-9-]+.(blob|file|queue|table|dfs|z8.web).core.windows.net/.*?sig=[a-zA-Z0-9%]{30,}`),
		Keywords:    []string{"sig="},
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-storage-credential-bloburl",
			"https://myacct.blob.core.windows.net/a?sp=r&sr=b&sig="+secrets.NewSecret(alphaNumeric("43"))),
	}
	return validate(r, tps, nil)
}

// CSCAN0050, CSCAN0060, CSCAN0070 - covered in PrivateKey.go

// CSCAN0080 looks for 'Password' in XML file

func AzurePasswordDecryptionkey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0090 - Found Azure password, symmetric key or storage credential in source file.",
		RuleID:      "azure-password-machinekey",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`(decryptionKey\s*\=\s*['"].*['"]|validationKey\s*\=\s*['"].*['"])`),
		Keywords:    []string{"decryptionKey", "validationKey"},
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-password-machinekey",
			"<machineKey decryptionKey='"+secrets.NewSecret(alphaNumeric("43"))+"' validationKey='"+secrets.NewSecret(alphaNumeric("43"))+"' useMachineContainer='true'>"),
	}
	return validate(r, tps, nil)
}

func AzurePasswordAddKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0090 - Found Azure password, symmetric key or storage credential in source file.",
		RuleID:      "azure-password-addkey",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`[<add].*([key](s|[0-9])?|(credential)s?|(secret)(s|S|[0-9])?|[password|token|key](primary|secondary|orsas|sas|encrypted))['"]\s*value\s*=['"].*['"]`),
		Keywords:    []string{"add"},
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-password-addkey",
			"<add key='primary' value='"+secrets.NewSecret(alphaNumeric("200")+"' >")),
	}
	return validate(r, tps, nil)
}

func AzurePasswordConnString() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0090 - Found Azure password, symmetric key or storage credential in source file.",
		RuleID:      "azure-password-connstring",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`(connectionstring|connstring)[^=]*?=["'][^"']*?(password)=[^\$\s;][^"'\s]*?(;|['"])`),
		Keywords:    []string{"connectionstring", "connstring", "password"},
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-password-connstring",
			//connstring='password=secret123;Server=localhost;'
			"connstring='Server=localhost;password="+secrets.NewSecret(alphaNumeric("23")+"'")),
	}
	return validate(r, tps, nil)
}

func AzurePasswordValueString() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0090 - Found Azure password, symmetric key or storage credential in source file.",
		RuleID:      "azure-password-value-string",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`value\s?=\s?['"]((([A-Za-z0-9+/]){4}){1,200})==['"]`),
		Keywords:    []string{"value"},
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-password-value-string",
			"value='"+secrets.NewSecret(alphaNumeric("20")+"=='")),
	}
	return validate(r, tps, nil)
}

func AzurePassworduidpw() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0090, CSCAN0150 - Found Azure password, symmetric key or storage credential in source file.",
		RuleID:      "azure-password-uidpw",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`((user) ?(id|name)|uid)=.{2,128}?\s*?;\s*?((password|(pwd))=[^'$%@'";\[\{][^;"']{2,350}?(;|"|'))`),
		Keywords:    []string{"uid", "user", "password", "pwd"},
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-password-uidpw",
			`uid=testuser;pwd=`+secrets.NewSecret(alphaNumeric("86")+";")),
	}
	return validate(r, tps, nil)
}

// TODO: Come back to the two XML passwords below
// func AzurePasswordXMLCredential() *config.Rule {
// 	// define rule
// 	r := config.Rule{
// 		Description: "CSCAN0090, CSCAN0150 - Found Azure password, symmetric key or storage credential in source file.",
// 		RuleID:      "azure-password-xml-credential",
// 		SecretGroup: 1,
// 		Regex: generateUniqueTokenRegex(`<credential>\s?name=['"][^"]*(key(s|[0-9])?|credential(s)?|secret(s|[0-9])?|password|token|key(primary|secondary|orsas|encrypted))['"](\s*value\s*=['"][^"]+['"].*?</credential>)`),
// 	}

// 	// validate
// 	tps := []string{
// 		generateSampleSecret("azure-password-xml-credential",
// 			"<credential>name='primary_key' value='" + secrets.NewSecret(alphaNumeric("86") + "'</credential>")),
// 	}
// 	return validate(r, tps, nil)
// }

// func AzurePasswordXMLValue() *config.Rule {
// 	// define rule
// 	r := config.Rule{
// 		Description: "CSCAN0090, CSCAN0150 - Found Azure password, symmetric key or storage credential in source file.",
// 		RuleID:      "azure-password-xml-value",
// 		SecretGroup: 1,
// 		Regex: generateUniqueTokenRegex(`<setting\sname=.?password.?>.*<value>.+</value>`),
// 	}

// 	// validate
// 	tps := []string{
// 		generateSampleSecret("azure-password-xml-value",
// 			//<setting name='password'><value>testpassword123</value>
// 			"<setting name='password'><value>" + secrets.NewSecret(alphaNumeric("86") + "</value>")),
// 	}
// 	return validate(r, tps, nil)
// }

// func AzurePasswordSSISProperty() *config.Rule {
// 	// define rule
// 	r := config.Rule{
// 		Description: "CSCAN0090 - Found Azure password, symmetric key or storage credential in source file.",
// 		RuleID:      "azure-password-ssis",
// 		SecretGroup: 1,
// 		Regex: generateUniqueTokenRegex(`(?s)<SSIS:Parameter\n?\s*SSIS:Name="password">.*?<SSIS:Property\n?\s*SSIS:Name="value">[^><#$\[\{\(]+</SSIS:Property>`),
// 	}

// 	// validate
// 	tps := []string{
// 		generateSampleSecret("azure-password-ssis",
// 			`
// 			This is a random text string that contains some characters>
// 			` + secrets.NewSecret(alphaNumeric("86") + "==")),
// 	}
// 	return validate(r, tps, nil)
// }

func AzureNetworkCredential() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0160 - Found Azure domain credential in source file.",
		RuleID:      "azure-network-credential",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`NetworkCredential\((\s*).*,(\s*).*,(\s*)(corp|europe|middleeast|northamerica|southpacific|southamerica|fareast|africa|redmond|exchange|extranet|partners|extranettest|parttest|noe|ntdev|ntwksta|sys-wingroup|windeploy|wingroup|winse|segroup|xcorp|xrep|phx|gme|usme|cdocidm|mslpa)\)`),
		Keywords:    []string{"NetworkCredential"},
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-network-credential",
			"NetworkCredential(username, password, europe)"),
	}
	return validate(r, tps, nil)
}

func AzureNetworkCredentialSchtasks() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0160 - Found Azure domain credential in source file.",
		RuleID:      "azure-network-credential-schtasks",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`schtasks.*/ru\s(corp|europe|middleeast|northamerica|southpacific|southamerica|fareast|africa|redmond|exchange|extranet|partners|extranettest|parttest|noe|ntdev|ntwksta|sys\-wingroup|windeploy|wingroup|winse|segroup|xcorp|xrep|phx|gme|usme|cdocidm|mslpa).*/rp.*`),
		Keywords:    []string{"schtasks"},
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-network-credential-schtasks",
			`schtasks /create /tn corp-daily-backup /tr \corp\backup.bat /ru corp\admin /rp password /sc daily`),
	}
	return validate(r, tps, nil)
}

func AzureNetworkCredentialDotNet() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0160 - Found Azure domain credential in source file.",
		RuleID:      "azure-network-credential-dotnet",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`new-object\s*System.Net.NetworkCredential\(.*?,\s*['"][^"]+['"]`),
		Keywords:    []string{"NetworkCredential"},
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-network-credential-dotnet",
			"New-Object System.Net.NetworkCredential(username, '"+secrets.NewSecret(alphaNumeric("86"))+"')"),
	}
	return validate(r, tps, nil)
}

func AzureDevTFVCSecrets() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0200 - Found Azure DevDiv TFVC repo secrets.",
		RuleID:      "azure-devtfvc-secrets",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`enc_username=.+[\n\r\s]+enc_password=.{3,}`),
		Keywords:    []string{"enc_username", "enc_password"},
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-devtfvc-secrets",
			"enc_username=myusername enc_password="+secrets.NewSecret(alphaNumeric("86"))),
	}
	return validate(r, tps, nil)
}

func AzureDevopsPAT() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0240 - Found Azure Devops personal access token in source file.",
		RuleID:      "azure-devops-pat",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`(access_token).*?['="][a-zA-Z0-9/+]{10,99}['"]`),
		Keywords:    []string{"access_token"},
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-devops-pat",
			"access_token=='"+secrets.NewSecret(hex("52"))+"'"),
	}
	return validate(r, tps, nil)
}

// func AzurePowershellTokenCache() *config.Rule {
// 	// define rule
// 	r := config.Rule{
// 		Description: "CSCAN0270 - Found Azure Subscription Token Cache.",
// 		RuleID:      "azure-powershell-tokencache",
// 		SecretGroup: 1,
// 		// Below finds the example on Regex101.com! So not sure what's happening here.
// 		Regex: generateUniqueTokenRegex(`["']TokenCache["']\s*:\s*\{\s*["']CacheData["']\s*:\s*["'][a-zA-Z0-9/\+]{86}`),
// 	}

// 	// validate
// 	tps := []string{
// 		generateSampleSecret("azure-powershell-tokencache",
// 			"'TokenCache': { 'CacheData': '" + secrets.NewSecret(alphaNumeric("86")) + "'"),
// 	}
// 	return validate(r, tps, nil)
// }
