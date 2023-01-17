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
		Regex: generateUniqueTokenRegex(`MII[a-z0-9=_\-]{200}`),
		Keywords: []string{"MII"},
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-app-service-deployment-secrets",
			"MII" + secrets.NewSecret(alphaNumeric("200"))),
	}
	return validate(r, tps, nil)
}

func AzureStorageCredential1() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0030 - Found Azure storage credential in source code file.",
		RuleID:      "azure-storage-credential-1",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`$(//|/\*)[ \t]{0,10}[a-zA-Z0-9/+]{86}==`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-storage-credential-1",
			"/n" + "//" + secrets.NewSecret(alphaNumeric("86") + "==")),
	}
	return validate(r, tps, nil)
}

func AzureStorageCredential2() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0030 - Found Azure storage credential in source code file.",
		RuleID:      "azure-storage-credential-2",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`\n[ \t]{0,50}(//|/\*)[ \t]{0,10}[a-zA-Z0-9/+]{43}=[^{@\d%]`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-storage-credential-2",
		"\n\t\t//\t\t" + secrets.NewSecret(alphaNumeric("43") + "=a")),
	}
	return validate(r, tps, nil)
}

func AzureStorageCredential3() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0030 - Found Azure storage credential in source code file.",
		RuleID:      "azure-storage-credential-3",
		SecretGroup: 1,
		// Define a regex rule to search for
		Regex: generateUniqueTokenRegex(`\n[^\r\n]{0,400}[>|'|=|"][a-zA-Z0-9/+]{86}==`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-storage-credential-3",
		// Create a test string that matches the regex
		"\n\t\t//\t\t" + secrets.NewSecret(alphaNumeric("86") + "=a")),
	}
	return validate(r, tps, nil)
}

func AzureStorageCredential4() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0030 - Found Azure storage credential in source code file.",
		RuleID:      "azure-storage-credential-4",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`\n[^\r\n]{0,400}[>|'|=|"][a-zA-Z0-9/+]{43}=[^{@\d%]`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-storage-credential-4",
			"MII" + secrets.NewSecret(alphaNumeric("200"))),
	}
	return validate(r, tps, nil)
}


func AzureStorageCredential5() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0030 - Found Azure storage credential in source code file.",
		RuleID:      "azure-storage-credential-5",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`(?i)\n[^\r\n]{0,800}((sig|sas|password)=|>)[a-zA-Z0-9%]{43,53}%3[dD][^{a-zA-Z0-9%]`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-storage-credential-5",
			"MII" + secrets.NewSecret(alphaNumeric("200"))),
	}
	return validate(r, tps, nil)
}


func AzureStorageCredential6() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0030 - Found Azure storage credential in source code file.",
		RuleID:      "azure-storage-credential-6",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`(?i)\n.*((user) ?(id|name)|uid)=.{2,128}?\s*?;\s*?((password)|(pwd))=[^'$%&gt;@'";\[\{][^;"']{2,350}?(;|"|')`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-storage-credential-6",
			"MII" + secrets.NewSecret(alphaNumeric("200"))),
	}
	return validate(r, tps, nil)
}

func AzureStorageCredential7() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0030 - Found Azure storage credential in source code file.",
		RuleID:      "azure-storage-credential-7",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`AccountKey\s*=\s*MII[a-zA-Z0-9/+]{43,}?={0,2}`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-storage-credential-7",
			"AccountKey = MII" + secrets.NewSecret(alphaNumeric("43") + "=")),
	}
	return validate(r, tps, nil)
}

func AzureStorageCredential8() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0100 - Found Azure storage credential in source code file.",
		RuleID:      "azure-storage-credential-8",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`&lt;XstoreAccountInfo[ -~&quot;\s\S\n\r\t]+accountSharedKey\s*=\s*"[^"]{30}[ -~&quot;\s\S\n\r\t]+/&gt;`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-storage-credential-8",
			"AccountKey = MII" + secrets.NewSecret(alphaNumeric("43"))),
	}
	return validate(r, tps, nil)
}

func AzureStorageCredential9() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0100 - Found Azure storage credential in source code file.",
		RuleID:      "azure-storage-credential-9",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`&lt;ServiceBusAccountInfo[ -~&quot;\s\S\n\r\t]+connectionString\s*=\s*"[^"]{30}[ -~&quot;\s\S\n\r\t]+/&gt;`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-storage-credential-9",
			"AccountKey = MII" + secrets.NewSecret(alphaNumeric("43"))),
	}
	return validate(r, tps, nil)
}

func AzureStorageCredential10() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0130 - Found Azure storage credential in MonitoringAgent config file.",
		RuleID:      "azure-storage-credential-10",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`Account moniker\s?=.*key\s?=.*`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-storage-credential-10",
			"decryptionKey='" + secrets.NewSecret(alphaNumeric("200") + "'")),
	}
	return validate(r, tps, nil)
}


// CSCAN0050, CSCAN0060, CSCAN0070 - covered in PrivateKey.go

// CSCAN0080 looks for 'Password' in XML file

func AzurePassword1() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0090 - Found Azure password, symmetric key or storage credential in source file.",
		RuleID:      "azure-password-1",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`&lt;machineKey[^&gt;]+(decryptionKey\s*\=\s*&quot;[a-fA-F0-9]{48,}|validationKey\s*\=\s*&quot;[a-fA-F0-9]{48,})[^&gt;]+&gt;`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-password-1",
			"AccountKey = MII" + secrets.NewSecret(alphaNumeric("43"))),
	}
	return validate(r, tps, nil)
}

func AzurePassword2() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0090 - Found Azure password, symmetric key or storage credential in source file.",
		RuleID:      "azure-password-2",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`(decryptionKey|validationKey)=['][a-zA-Z0-9][']`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-password-2",
			"decryptionKey='" + secrets.NewSecret(alphaNumeric("200") + "'")),
	}
	return validate(r, tps, nil)
}

func AzurePassword3() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0090 - Found Azure password, symmetric key or storage credential in source file.",
		RuleID:      "azure-password-3",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`&lt;add\skey=&quot;[^&quot;]*([kK][eE][yY]([sS]|[0-9])?|([cC]redential|CREDENTIAL)[sS]?|([sS]ecret|SECRET)(s|S|[0-9])?|[pP]ass[wW]ord|PASSWORD|[tT]oken|TOKEN|([kK]ey|KEY)([pP]rimary|PRIMARY|[sS]econdary|SECONDARY|[oO]r[sS]as|SAS|[eE]ncrypted|ENCRYPTED))&quot;\s*value\s*=&quot;[^&quot;]+&quot;`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-password-3",
			"decryptionKey='" + secrets.NewSecret(alphaNumeric("200") + "'")),
	}
	return validate(r, tps, nil)
}

func AzurePassword4() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0090 - Found Azure password, symmetric key or storage credential in source file.",
		RuleID:      "azure-password-4",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`&lt;add\skey=&quot;[^&quot;]+&quot;\s*value=&quot;[^&quot;]*([eE]ncrypted|ENCRYPTED).?([sS]ecret|SECRET)[^&quot;]+&quot;\s*/&gt;`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-password-4",
			"decryptionKey='" + secrets.NewSecret(alphaNumeric("200") + "'")),
	}
	return validate(r, tps, nil)
}

func AzurePassword5() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0090 - Found Azure password, symmetric key or storage credential in source file.",
		RuleID:      "azure-password-5",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`([cC]onnection[sS]tring|[cC]onn[sS]tring)[^=]*?=["'][^"']*?([pP]ass[wW]ord|PASSWORD)=[^\$\s;][^"'\s]*?(;|")`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-password-5",
			"decryptionKey='" + secrets.NewSecret(alphaNumeric("200") + "'")),
	}
	return validate(r, tps, nil)
}

func AzurePassword6() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0090 - Found Azure password, symmetric key or storage credential in source file.",
		RuleID:      "azure-password-6",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`[vV]alue\s?=\s?&quot;((([A-Za-z0-9+/]){4}){1,200})==&quot;`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-password-6",
			"decryptionKey='" + secrets.NewSecret(alphaNumeric("200") + "'")),
	}
	return validate(r, tps, nil)
}

func AzurePassword7() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0090, CSCAN0150 - Found Azure password, symmetric key or storage credential in source file.",
		RuleID:      "azure-password-7",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`\n[^\r\n]{0,400}(>|'|=|")[a-zA-Z0-9/+]{86}==`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-password-7",
			"decryptionKey='" + secrets.NewSecret(alphaNumeric("200") + "'")),
	}
	return validate(r, tps, nil)
}

func AzurePassword8() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0090 - Found Azure password, symmetric key or storage credential in source file.",
		RuleID:      "azure-password-8",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`n[^\r\n]{0,400}(>|'|=|")[a-zA-Z0-9/+]{43}=[^{@]`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-password-8",
			`
			This is a random text string that contains some characters>
			` + secrets.NewSecret(alphaNumeric("86") + "==")),
	}
	return validate(r, tps, nil)
}

func AzurePassword9() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0090, CSCAN0150 - Found Azure password, symmetric key or storage credential in source file.",
		RuleID:      "azure-password-9",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`\n[^\r\n]{0,800}((sig|SIG|sas|SAS|([pP]ass[wW]ord|PASSWORD))=|>)[a-zA-Z0-9%]{43,53}%3[dD][^{a-zA-Z0-9%]`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-password-9",
			`
			This is a random text string that contains some characters>
			` + secrets.NewSecret(alphaNumeric("86") + "==")),
	}
	return validate(r, tps, nil)
}

func AzurePassword10() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0090, CSCAN0150 - Found Azure password, symmetric key or storage credential in source file.",
		RuleID:      "azure-password-10",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`\n.*(([uU]ser|USER) ?([iI]d|ID|[nN]ame|NAME)|[uU]id|UID)=.{2,128}?\s*?;\s*?(([pP]ass[wW]ord|PASSWORD)|([pP]wd|PWD))=[^'$%&gt;@'";\[\{][^;"']{2,350}?(;|"|')`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-password-10",
			`
			This is a random text string that contains some characters>
			` + secrets.NewSecret(alphaNumeric("86") + "==")),
	}
	return validate(r, tps, nil)
}

func AzurePassword11() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0090, CSCAN0150 - Found Azure password, symmetric key or storage credential in source file.",
		RuleID:      "azure-password-11",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`&lt;[cC]redential\sname="[^"]*([kK][eE][yY]([sS]|[0-9])?|[cC]redential(s)?|[sS]ecret(s|[0-9])?|[pP]ass[wW]ord|PASSWORD|[tT]oken|[kK]ey([pP]rimary|[sS]econdary|[oO]r[sS]as|[eE]ncrypted))"(\s*value\s*="[^"]+".*?/&gt;|[^&gt;\s]*&gt;.*?&lt;/[cC]redential&gt;)`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-password-11",
			`
			This is a random text string that contains some characters>
			` + secrets.NewSecret(alphaNumeric("86") + "==")),
	}
	return validate(r, tps, nil)
}

func AzurePassword12() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0090, CSCAN0150 - Found Azure password, symmetric key or storage credential in source file.",
		RuleID:      "azure-password-12",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`&lt;[sS]etting\sname="[^"]*[pP]ass[wW]ord".*[\r\n]*\s*&lt;[vV]alue&gt;.+&lt;/[vV]alue&gt;`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-password-12",
			`
			This is a random text string that contains some characters>
			` + secrets.NewSecret(alphaNumeric("86") + "==")),
	}
	return validate(r, tps, nil)
}

func AzurePassword13() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0090 - Found Azure password, symmetric key or storage credential in source file.",
		RuleID:      "azure-password-13",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`(?s)&lt;SSIS:Parameter\n?\s*SSIS:Name="[pP]ass[wW]ord"&gt;.*?&lt;SSIS:Property\n?\s*SSIS:Name="[vV]alue"&gt;[^&gt;&lt;#$\[\{\(]+&lt;/SSIS:Property&gt;`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-password-13",
			`
			This is a random text string that contains some characters>
			` + secrets.NewSecret(alphaNumeric("86") + "==")),
	}
	return validate(r, tps, nil)
}

func AzurePassword14() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0090 - Found Azure password, symmetric key or storage credential in source file.",
		RuleID:      "azure-password-14",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`&lt;SSIS:Property\n?\s*SSIS:Name="[vV]alue"&gt;.*["'][pP]ass[wW]ord["']:["'][^"']+["']`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-password-14",
			`
			This is a random text string that contains some characters>
			` + secrets.NewSecret(alphaNumeric("86") + "==")),
	}
	return validate(r, tps, nil)
}

func AzurePassword15() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0090 - Found Azure password, symmetric key or storage credential in source file.",
		RuleID:      "azure-password-15",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`userPWD="[a-zA-Z0-9]{60}"`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-password-15",
			`
			This is a random text string that contains some characters>
			` + secrets.NewSecret(alphaNumeric("86") + "==")),
	}
	return validate(r, tps, nil)
}

func AzureNetworkCredential1() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0160 - Found Azure domain credential in source file.",
		RuleID:      "azure-network-credential-1",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`NetworkCredential\(.*,.*,([cC][oO][rR][pP]|[eE][uU][rR][oO][pP][eE]|[mM][iI][dD][dD][lL][eE][eE][aA][sS][tT]|[nN][oO][rR][tT][hH][aA][mM][eE][rR][iI][cC][aA]|[sS][oO][uU][tT][hH][pP][aA][cC][iI][fF][iI][cC]|[sS][oO][uU][tT][hH][aA][mM][eE][rR][iI][cC][aA]|[fF][aA][rR][eE][aA][sS][tT]|[aA][fF][rR][iI][cC][aA]|[rR][eE][dD][mM][oO][nN][dD]|[eE][xX][cC][hH][aA][nN][gG][eE]|[eE][xX][tT][rR][aA][nN][eE][tT]|[pP][aA][rR][tT][nN][eE][rR][sS]|[eE][xX][tT][rR][aA][nN][eE][tT][tT][eE][sS][tT]|[pP][aA][rR][tT][tT][eE][sS][tT]|[nN][oO][eE]|[nN][tT][dD][eE][vV]|[nN][tT][wW][kK][sS][tT][aA]|[sS][yY][sS]\-[wW][iI][nN][gG][rR][oO][uU][pP]|[wW][iI][nN][dD][eE][pP][lL][oO][yY]|[wW][iI][nN][gG][rR][oO][uU][pP]|[wW][iI][nN][sS][eE]|[sS][eE][gG][rR][oO][uU][pP]|[xX][cC][oO][rR][pP]|[xX][rR][eE][pP]|[pP][hH][xX]|[gG][mM][eE]|[uU][sS][mM][eE]|[cC][dD][oO][cC][iI][dD][mM]|[mM][sS][lL][pP][aA])\\.*`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-network-credential-1",
			"NetworkCredential(username, password, europe)"),
	}
	return validate(r, tps, nil)
}

func AzureNetworkCredential2() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0160 - Found Azure domain credential in source file.",
		RuleID:      "azure-network-credential-2",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`[nN][eE][tT]\s[uU][sS][eE].*\/[uU]\:([cC][oO][rR][pP]|[eE][uU][rR][oO][pP][eE]|[mM][iI][dD][dD][lL][eE][eE][aA][sS][tT]|[nN][oO][rR][tT][hH][aA][mM][eE][rR][iI][cC][aA]|[sS][oO][uU][tT][hH][pP][aA][cC][iI][fF][iI][cC]|[sS][oO][uU][tT][hH][aA][mM][eE][rR][iI][cC][aA]|[fF][aA][rR][eE][aA][sS][tT]|[aA][fF][rR][iI][cC][aA]|[rR][eE][dD][mM][oO][nN][dD]|[eE][xX][cC][hH][aA][nN][gG][eE]|[eE][xX][tT][rR][aA][nN][eE][tT]|[pP][aA][rR][tT][nN][eE][rR][sS]|[eE][xX][tT][rR][aA][nN][eE][tT][tT][eE][sS][tT]|[pP][aA][rR][tT][tT][eE][sS][tT]|[nN][oO][eE]|[nN][tT][dD][eE][vV]|[nN][tT][wW][kK][sS][tT][aA]|[sS][yY][sS]\-[wW][iI][nN][gG][rR][oO][uU][pP]|[wW][iI][nN][dD][eE][pP][lL][oO][yY]|[wW][iI][nN][gG][rR][oO][uU][pP]|[wW][iI][nN][sS][eE]|[sS][eE][gG][rR][oO][uU][pP]|[xX][cC][oO][rR][pP]|[xX][rR][eE][pP]|[pP][hH][xX]|[gG][mM][eE]|[uU][sS][mM][eE]|[cC][dD][oO][cC][iI][dD][mM]|[mM][sS][lL][pP][aA])\\.*`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-network-credential-2",
			`Net use \server\u:corp\share /user:corp\username`),
	}
	return validate(r, tps, nil)
}

func AzureNetworkCredential3() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0160 - Found Azure domain credential in source file.",
		RuleID:      "azure-network-credential-3",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`[sS][cC][hH][tT][aA][sS][kK][sS].*/[rR][uU]\s([cC][oO][rR][pP]|[eE][uU][rR][oO][pP][eE]|[mM][iI][dD][dD][lL][eE][eE][aA][sS][tT]|[nN][oO][rR][tT][hH][aA][mM][eE][rR][iI][cC][aA]|[sS][oO][uU][tT][hH][pP][aA][cC][iI][fF][iI][cC]|[sS][oO][uU][tT][hH][aA][mM][eE][rR][iI][cC][aA]|[fF][aA][rR][eE][aA][sS][tT]|[aA][fF][rR][iI][cC][aA]|[rR][eE][dD][mM][oO][nN][dD]|[eE][xX][cC][hH][aA][nN][gG][eE]|[eE][xX][tT][rR][aA][nN][eE][tT]|[pP][aA][rR][tT][nN][eE][rR][sS]|[eE][xX][tT][rR][aA][nN][eE][tT][tT][eE][sS][tT]|[pP][aA][rR][tT][tT][eE][sS][tT]|[nN][oO][eE]|[nN][tT][dD][eE][vV]|[nN][tT][wW][kK][sS][tT][aA]|[sS][yY][sS]\-[wW][iI][nN][gG][rR][oO][uU][pP]|[wW][iI][nN][dD][eE][pP][lL][oO][yY]|[wW][iI][nN][gG][rR][oO][uU][pP]|[wW][iI][nN][sS][eE]|[sS][eE][gG][rR][oO][uU][pP]|[xX][cC][oO][rR][pP]|[xX][rR][eE][pP]|[pP][hH][xX]|[gG][mM][eE]|[uU][sS][mM][eE]|[cC][dD][oO][cC][iI][dD][mM]|[mM][sS][lL][pP][aA]).*/[rR][pP].*`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-network-credential-3",
			`Schtasks /create /tn corp-daily-backup /tr \corp\backup.bat /ru corp\admin /rp password /sc daily`),
	}
	return validate(r, tps, nil)
}

func AzureNetworkCredential4() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0160 - Found Azure domain credential in source file.",
		RuleID:      "azure-network-credential-4",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`[nN]ew-[oO]bject\s*System.Net.NetworkCredential\(.*?,\s*"[^"]+"`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-network-credential-4",
			`New-Object System.Net.NetworkCredential(username, "password")`),
	}
	return validate(r, tps, nil)
}

func AzureDevTFVCSecrets() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0200 - Found Azure DevDiv TFVC repo secrets.",
		RuleID:      "azure-devtfvc-secrets",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`[eE][nN][cC]_[uU][sS][eE][rR][nN][aA][mM][eE]=[\w]+[\r\n]+[eE][nN][cC]_[pP][aA][sS][sS][wW][oO][rR][dD]=[\w]+`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-devtfvc-secrets",
			`enc_username=myusername\r\nenc_password=mypassword`),
	}
	return validate(r, tps, nil)
}

func AzureVSTSPAT1() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0240 - Found Azure Found Vsts personal access token in source file.",
		RuleID:      "azure-vsts-pat1",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`([aA]ccess_?[tT]oken|ACCESS_?TOKEN).*?['="][a-z2-7]{52}('|"|\s|[\r\n]+)`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-vsts-pat1",
			`Access_token=='a2b2c3d4e5a2b2c3d4e5a2b2c3d4e5a2b2c3d4e5a2b2c3d4e5a2'`),
	}
	return validate(r, tps, nil)
}

func AzureVSTSPAT2() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0240 - Found Azure Found Vsts personal access token in source file.",
		RuleID:      "azure-vsts-pat2",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`[pP]ass[wW]ord\s+[a-z2-7]{52}(\s|[\r\n]+)`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-vsts-pat2",
			`Access_token=='a2b2c3d4e5a2b2c3d4e5a2b2c3d4e5a2b2c3d4e5a2b2c3d4e5a2'`),
	}
	return validate(r, tps, nil)
}

func AzureVSTSPAT3() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0240 - Found Azure Vsts personal access token in source file.",
		RuleID:      "azure-vsts-pat3",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`([aA]ccess_?[tT]oken|ACCESS_?TOKEN).*?[>|'|=|"][a-zA-Z0-9/+]{70}==`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-vsts-pat3",
			`Access_token=='a2b2c3d4e5a2b2c3d4e5a2b2c3d4e5a2b2c3d4e5a2b2c3d4e5a2'`),
	}
	return validate(r, tps, nil)
}

func AzurePowershellTokenCache() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0270 - Found Azure Subscription Token Cache.",
		RuleID:      "azure-powershell-tokencache",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`["']TokenCache["']\s*:\s*\{\s*["']CacheData["']\s*:\s*["'][a-zA-Z0-9/\+]{86}`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-powershell-tokencache",
			`Access_token=='a2b2c3d4e5a2b2c3d4e5a2b2c3d4e5a2b2c3d4e5a2b2c3d4e5a2'`),
	}
	return validate(r, tps, nil)
}
