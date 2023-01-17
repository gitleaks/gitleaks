package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// Rules come from https://www.powershellgallery.com/packages/AzSK.AzureDevOps/0.9.8/Content/Framework%5CConfigurations%5CSVT%5CAzureDevOps%5CCredentialPatterns.xml
// Only rules with 'ContentSearchPatterns' have been used.

func AzureBase64EncodedCertificate() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0020 - Found Azure base64 encoded certificate with private key in source file. Validate file contains secrets, remove, roll credential, and use approved store.",
		RuleID:      "azure-base64-encoded-certificate",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`MII[a-z0-9=_\-]{200}`),
		Keywords: []string{"MII"},
		
	}

	tps := []string{
		generateSampleSecret("azure-base64-encoded-certificate",
			"MII" + secrets.NewSecret(alphaNumeric("200"))),
	}
	return validate(r, tps, nil)
}

func AzureAppServiceDeploymentSecrets() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0030 - Found Azure app service deployment secrets in publish settings file. Validate file contains secrets, remove, roll credential, and use approved store.",
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
		Description: "CSCAN0030 - Found Azure storage credential in source code file. Validate file contains secrets, remove, roll credential, and use approved store.",
		RuleID:      "azure-storage-credential-1",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`\n[ \t]{0,50}(//|/\*)[ \t]{0,10}[a-zA-Z0-9/+]{86}==`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-storage-credential-1",
			"MII" + secrets.NewSecret(alphaNumeric("200"))),
	}
	return validate(r, tps, nil)
}

func AzureStorageCredential2() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0030 - Found Azure storage credential in source code file. Validate file contains secrets, remove, roll credential, and use approved store.",
		RuleID:      "azure-storage-credential-2",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`\n[ \t]{0,50}(//|/\*)[ \t]{0,10}[a-zA-Z0-9/+]{43}=[^{@\d%]`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-storage-credential-2",
			"MII" + secrets.NewSecret(alphaNumeric("200"))),
	}
	return validate(r, tps, nil)
}

func AzureStorageCredential3() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0030 - Found Azure storage credential in source code file. Validate file contains secrets, remove, roll credential, and use approved store.",
		RuleID:      "azure-storage-credential-3",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`\n[^\r\n]{0,400}[>|'|=|"][a-zA-Z0-9/+]{86}==`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-storage-credential-3",
			"MII" + secrets.NewSecret(alphaNumeric("200"))),
	}
	return validate(r, tps, nil)
}

func AzureStorageCredential4() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0030 - Found Azure storage credential in source code file. Validate file contains secrets, remove, roll credential, and use approved store.",
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
		Description: "CSCAN0030 - Found Azure storage credential in source code file. Validate file contains secrets, remove, roll credential, and use approved store.",
		RuleID:      "azure-storage-credential-5",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`\n[^\r\n]{0,800}((sig|SIG|sas|SAS|([pP]ass[wW]ord|PASSWORD))=|>)[a-zA-Z0-9%]{43,53}%3[dD][^{a-zA-Z0-9%]`),
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
		Description: "CSCAN0030 - Found Azure storage credential in source code file. Validate file contains secrets, remove, roll credential, and use approved store.",
		RuleID:      "azure-storage-credential-6",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`\n.*(([uU]ser|USER) ?([iI]d|ID|[nN]ame|NAME)|[uU]id|UID)=.{2,128}?\s*?;\s*?(([pP]ass[wW]ord|PASSWORD)|([pP]wd|PWD))=[^'$%&gt;@'";\[\{][^;"']{2,350}?(;|"|')`),
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
		Description: "CSCAN0030 - Found Azure storage credential in source code file. Validate file contains secrets, remove, roll credential, and use approved store.",
		RuleID:      "azure-storage-credential-7",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`AccountKey\s*=\s*MII[a-zA-Z0-9/+]{43,}?={0,2}`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-storage-credential-7",
			"AccountKey = MII" + secrets.NewSecret(alphaNumeric("43"))),
	}
	return validate(r, tps, nil)
}

func AzureStorageCredential8() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0100 - Found Azure storage credential in source code file. Validate file contains secrets, remove, roll credential, and use approved store.",
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
		Description: "CSCAN0100 - Found Azure storage credential in source code file. Validate file contains secrets, remove, roll credential, and use approved store.",
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
		Description: "CSCAN0130 - Found Azure storage credential in MonitoringAgent config file. Validate file contains secrets, remove, roll credential, and use approved store.",
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
		Description: "CSCAN0090 - Found Azure password, symmetric key or storage credential in source file. Validate file contains secrets, remove, roll credential, and use approved store.",
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
		Description: "CSCAN0090 - Found Azure password, symmetric key or storage credential in source file. Validate file contains secrets, remove, roll credential, and use approved store.",
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

//   <ContentSearcher>
//     <Name>ConfigFile</Name>
//     <RuleId>CSCAN0090</RuleId>
//     <ResourceMatchPattern>\.(config|cscfg|conf|json|jsx?|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|tsx?|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|sh|m|php|py|xaml|keys|cmd|rds|loadtest|properties|vbs|ccf|user)$|(hubot|project.params)</ResourceMatchPattern>
//     <ContentSearchPatterns>
//       <string></string>
//       <string></string>
//       <string>&lt;add\skey=&quot;[^&quot;]*([kK][eE][yY]([sS]|[0-9])?|([cC]redential|CREDENTIAL)[sS]?|([sS]ecret|SECRET)(s|S|[0-9])?|[pP]ass[wW]ord|PASSWORD|[tT]oken|TOKEN|([kK]ey|KEY)([pP]rimary|PRIMARY|[sS]econdary|SECONDARY|[oO]r[sS]as|SAS|[eE]ncrypted|ENCRYPTED))&quot;\s*value\s*=&quot;[^&quot;]+&quot;</string>
//       <string>&lt;add\skey=&quot;[^&quot;]+&quot;\s*value=&quot;[^&quot;]*([eE]ncrypted|ENCRYPTED).?([sS]ecret|SECRET)[^&quot;]+&quot;\s*/&gt;</string>
//       <string>([cC]onnection[sS]tring|[cC]onn[sS]tring)[^=]*?=["'][^"']*?([pP]ass[wW]ord|PASSWORD)=[^\$\s;][^"'\s]*?(;|")</string>
//       <string>[vV]alue\s?=\s?&quot;((([A-Za-z0-9+/]){4}){1,200})==&quot;</string>
//       <string>\n[^\r\n]{0,400}(>|'|=|")[a-zA-Z0-9/+]{86}==</string>
//       <string>\n[^\r\n]{0,400}(>|'|=|")[a-zA-Z0-9/+]{43}=[^{@]</string>
//       <string>\n[^\r\n]{0,800}((sig|SIG|sas|SAS|([pP]ass[wW]ord|PASSWORD))=|>)[a-zA-Z0-9%]{43,53}%3[dD][^{a-zA-Z0-9%]</string>
//       <string>\n.*(([uU]ser|USER) ?([iI]d|ID|[nN]ame|NAME)|[uU]id|UID)=.{2,128}?\s*?;\s*?(([pP]ass[wW]ord|PASSWORD)|([pP]wd|PWD))=[^'$%&gt;@'";\[\{][^;"']{2,350}?(;|"|')</string>
//       <string>&lt;[cC]redential\sname="[^"]*([kK][eE][yY]([sS]|[0-9])?|[cC]redential(s)?|[sS]ecret(s|[0-9])?|[pP]ass[wW]ord|PASSWORD|[tT]oken|[kK]ey([pP]rimary|[sS]econdary|[oO]r[sS]as|[eE]ncrypted))"(\s*value\s*="[^"]+".*?/&gt;|[^&gt;\s]*&gt;.*?&lt;/[cC]redential&gt;)</string>
//       <string>&lt;[sS]etting\sname="[^"]*[pP]ass[wW]ord".*[\r\n]*\s*&lt;[vV]alue&gt;.+&lt;/[vV]alue&gt;</string>
//       <string>(?s)&lt;SSIS:Parameter\n?\s*SSIS:Name="[pP]ass[wW]ord"&gt;.*?&lt;SSIS:Property\n?\s*SSIS:Name="[vV]alue"&gt;[^&gt;&lt;#$\[\{\(]+&lt;/SSIS:Property&gt;</string>
//       <string>&lt;SSIS:Property\n?\s*SSIS:Name="[vV]alue"&gt;.*["'][pP]ass[wW]ord["']:["'][^"']+["']</string>
//     </ContentSearchPatterns>
//     <ContentSearchFilters>
//       <ContentFilter>
//         <Name>Key Patterns ContentFilters</Name>
//         <Filters>
//           <string>key\s*=\s*"[^"]*AppKey[^"]*"\s+value\s*=\s*"[a-z]+"</string>
//           <string>key\s*=\s*"(?&lt;keygroup>[^"]*)"\s+value\s*=\s*"[^"]*\k&lt;keygroup>"</string>
//           <string>value\s*=\s*"(([a-z]+_[a-z]+)+"|[a-z]+( [a-z]+)+"|_+[a-z]+_+"|[a-z]+-[a-z]+-[a-z]+["-]|[a-z]+-[a-z]+"|[a-z]+\\[a-z]+"|\d+"|[^"]*ConnectionString")</string>
//           <string>AccountKey\s*=\s*MII[a-zA-Z0-9/+]{43,}={0,2}</string>
//           <string>Credentials?Type|ConnectionStringKey|notasecret|PartitionKey|notreal|insertkey|LookupKey|IgnoreKeys|SecretsService|SecretsTenantId|(Password|pwd|secret|credentials?)(Key|Location)|KeyManager|fake|vault</string>
//           <string>value=&quot;(true|false|@\(api|ssh\-rsa 2048|invalid|to be|a shared secret|secreturi|clientsecret|Overr?idden by|someValue|SOME\-SIGNING\-KEY|TokenBroker|UNKNOWN|Client Secret of|Junk Credentials|Default\-|__BOOTSTRAPKEY_|CacheSecret|CatalogCert|CosmosCredentials|DeleteServiceCert|EmailCredentials|MetricsConnection|SangamCredentials|SubscriptionConnection|Enter_your_|My_Issuer|ScaleUnitXstoreSharedKey|private_powerapps|TestSecret|foo_|bar_|temp_|__WinfabricTestInfra|configured|SecretFor|Test|XSTORE_KEY|ServiceBusDiagnosticXstoreSharedKey|BoxApplicationKey|googleapps)</string>
//           <string>(SecurityHashcode|_AppKey&quot;|((credential|password|token)s?|(Account|access)Key=)&quot;[\s\r\n]*/|username"\s*value="|\.dll|(Secret|Token|Key|Credential)s?(Encryption|From|(Signing)?Certificate|Options|Thumbprint|Contacts|String|UserId)|Key(1;value1|word|s?Path|Index|Id|Store|WillDoWithoutValidation|:NamePattern|Name&quot;|Ref&quot;)|(Secret|Credential)s?(Name|Path)&quot;|(StrongName|Chaos\s?Mon|Redis|Registry|Registery|User|Insights?|Instrumentation|Match\()Key|(Certificate|cert)(Issuer|Subject)|rollingdate|skuId|HKEY_|AddServicePrincipalCredentials|Password Resets|SecretStore|(0|x|\*){8,})</string>
//           <string>=(?&lt;c>.)\k&lt;c>{3,}</string>
//           <string>(password|pwd)=&lt;[a-z0-9]+></string>
//         </Filters>
//       </ContentFilter>
//     </ContentSearchFilters>
//     <MatchDetails>Found password, symmetric key or storage credential in source file.</MatchDetails>
//     <Recommendation>Validate file contains secrets, remove, roll credential, and use approved store. For additional information on secret remediation see https://aka.ms/credscan </Recommendation>
//     <Severity>3</Severity>
//     <SearchValidatorClassName>Microsoft.Art.ContentSearch.SymmetricKeyValidator, Microsoft.Art.ContentSearch</SearchValidatorClassName>
//   </ContentSearcher>


// CSCAN0110, CSCAN0111, CSCAN0140, CSCAN0220 searches for generic passwords - covered elsewhere

// CSCAN0120 searches for Twilio keys - covered in twilio.go

//   <ContentSearcher>
//     <Name>AzureSecret</Name>
//     <RuleId>CSCAN0150</RuleId>
//     <ResourceMatchPattern>\.(xml|pubxml|definitions|ps1|wadcfgx|cmd|ccf|pbix)$</ResourceMatchPattern>
//     <ContentSearchPatterns>
//       <string>userPWD="[a-zA-Z0-9]{60}"</string>
//       <string>\n[^\r\n]{0,400}(>|'|=|")[a-zA-Z0-9/+]{43}=[^{@]</string>
//       <string>\n[^\r\n]{0,400}(>|'|=|"|#)[a-zA-Z0-9/+]{86}==</string>
//       <string>\n[^\r\n]{0,800}(([tT]oken|TOKEN|[sS]ecret|SECRET|sig|SIG|sas|SAS|([pP]ass[wW]ord|PASSWORD))=|>)[a-zA-Z0-9%]{43,53}%3[dD][^{a-zA-Z0-9%]</string>
//       <string>\n.*(([uU]ser|USER) ?([iI]d|ID|[nN]ame|NAME)|[uU]id|UID)=.{2,128}?\s*?;\s*?(([pP]ass[wW]ord|PASSWORD)|([pP]wd|PWD))=[^'$%&gt;@'";\[\{][^;"']{2,350}?(;|"|')</string>
//     </ContentSearchPatterns>
//     <MatchDetails>Found symmetric key or storage credential in source file.</MatchDetails>
//     <Recommendation>Validate file contains secrets, remove, roll credential, use an approved secret store.</Recommendation>
//     <Severity>3</Severity>
//     <SearchValidatorClassName>Microsoft.Art.ContentSearch.SymmetricKeyValidator, Microsoft.Art.ContentSearch</SearchValidatorClassName>
//   </ContentSearcher>


//   <ContentSearcher>
//     <Name>DomainPassword</Name>
//     <RuleId>CSCAN0160</RuleId>
//     <ResourceMatchPattern>\.cs$|\.c$|\.cpp$|\.ps1$|\.ps$|\.cmd$|\.bat$|\.log$|\.psd$|\.psm1$</ResourceMatchPattern>
//     <ContentSearchPatterns>
//       <string>NetworkCredential\(.*,.*,([cC][oO][rR][pP]|[eE][uU][rR][oO][pP][eE]|[mM][iI][dD][dD][lL][eE][eE][aA][sS][tT]|[nN][oO][rR][tT][hH][aA][mM][eE][rR][iI][cC][aA]|[sS][oO][uU][tT][hH][pP][aA][cC][iI][fF][iI][cC]|[sS][oO][uU][tT][hH][aA][mM][eE][rR][iI][cC][aA]|[fF][aA][rR][eE][aA][sS][tT]|[aA][fF][rR][iI][cC][aA]|[rR][eE][dD][mM][oO][nN][dD]|[eE][xX][cC][hH][aA][nN][gG][eE]|[eE][xX][tT][rR][aA][nN][eE][tT]|[pP][aA][rR][tT][nN][eE][rR][sS]|[eE][xX][tT][rR][aA][nN][eE][tT][tT][eE][sS][tT]|[pP][aA][rR][tT][tT][eE][sS][tT]|[nN][oO][eE]|[nN][tT][dD][eE][vV]|[nN][tT][wW][kK][sS][tT][aA]|[sS][yY][sS]\-[wW][iI][nN][gG][rR][oO][uU][pP]|[wW][iI][nN][dD][eE][pP][lL][oO][yY]|[wW][iI][nN][gG][rR][oO][uU][pP]|[wW][iI][nN][sS][eE]|[sS][eE][gG][rR][oO][uU][pP]|[xX][cC][oO][rR][pP]|[xX][rR][eE][pP]|[pP][hH][xX]|[gG][mM][eE]|[uU][sS][mM][eE]|[cC][dD][oO][cC][iI][dD][mM]|[mM][sS][lL][pP][aA])\\.*</string>
//       <string>[nN][eE][tT]\s[uU][sS][eE].*\/[uU]\:([cC][oO][rR][pP]|[eE][uU][rR][oO][pP][eE]|[mM][iI][dD][dD][lL][eE][eE][aA][sS][tT]|[nN][oO][rR][tT][hH][aA][mM][eE][rR][iI][cC][aA]|[sS][oO][uU][tT][hH][pP][aA][cC][iI][fF][iI][cC]|[sS][oO][uU][tT][hH][aA][mM][eE][rR][iI][cC][aA]|[fF][aA][rR][eE][aA][sS][tT]|[aA][fF][rR][iI][cC][aA]|[rR][eE][dD][mM][oO][nN][dD]|[eE][xX][cC][hH][aA][nN][gG][eE]|[eE][xX][tT][rR][aA][nN][eE][tT]|[pP][aA][rR][tT][nN][eE][rR][sS]|[eE][xX][tT][rR][aA][nN][eE][tT][tT][eE][sS][tT]|[pP][aA][rR][tT][tT][eE][sS][tT]|[nN][oO][eE]|[nN][tT][dD][eE][vV]|[nN][tT][wW][kK][sS][tT][aA]|[sS][yY][sS]\-[wW][iI][nN][gG][rR][oO][uU][pP]|[wW][iI][nN][dD][eE][pP][lL][oO][yY]|[wW][iI][nN][gG][rR][oO][uU][pP]|[wW][iI][nN][sS][eE]|[sS][eE][gG][rR][oO][uU][pP]|[xX][cC][oO][rR][pP]|[xX][rR][eE][pP]|[pP][hH][xX]|[gG][mM][eE]|[uU][sS][mM][eE]|[cC][dD][oO][cC][iI][dD][mM]|[mM][sS][lL][pP][aA])\\.*</string>
//       <string>[sS][cC][hH][tT][aA][sS][kK][sS].*/[rR][uU]\s([cC][oO][rR][pP]|[eE][uU][rR][oO][pP][eE]|[mM][iI][dD][dD][lL][eE][eE][aA][sS][tT]|[nN][oO][rR][tT][hH][aA][mM][eE][rR][iI][cC][aA]|[sS][oO][uU][tT][hH][pP][aA][cC][iI][fF][iI][cC]|[sS][oO][uU][tT][hH][aA][mM][eE][rR][iI][cC][aA]|[fF][aA][rR][eE][aA][sS][tT]|[aA][fF][rR][iI][cC][aA]|[rR][eE][dD][mM][oO][nN][dD]|[eE][xX][cC][hH][aA][nN][gG][eE]|[eE][xX][tT][rR][aA][nN][eE][tT]|[pP][aA][rR][tT][nN][eE][rR][sS]|[eE][xX][tT][rR][aA][nN][eE][tT][tT][eE][sS][tT]|[pP][aA][rR][tT][tT][eE][sS][tT]|[nN][oO][eE]|[nN][tT][dD][eE][vV]|[nN][tT][wW][kK][sS][tT][aA]|[sS][yY][sS]\-[wW][iI][nN][gG][rR][oO][uU][pP]|[wW][iI][nN][dD][eE][pP][lL][oO][yY]|[wW][iI][nN][gG][rR][oO][uU][pP]|[wW][iI][nN][sS][eE]|[sS][eE][gG][rR][oO][uU][pP]|[xX][cC][oO][rR][pP]|[xX][rR][eE][pP]|[pP][hH][xX]|[gG][mM][eE]|[uU][sS][mM][eE]|[cC][dD][oO][cC][iI][dD][mM]|[mM][sS][lL][pP][aA]).*/[rR][pP].*</string>
//       <string>[nN]ew-[oO]bject\s*System.Net.NetworkCredential\(.*?,\s*"[^"]+"</string>
//     </ContentSearchPatterns>
//     <ContentSearchFilters>
//       <ContentFilter>
//         <Name>Placeholder ContentFilters</Name>
//         <Filters>
//           <string>%1%</string>
//           <string>\$MIGUSER_PASSWORD</string>
//           <string>%miguser_pwd%</string>
//         </Filters>
//       </ContentFilter>
//     </ContentSearchFilters>
//     <MatchDetails>Found domain credential in source file.</MatchDetails>
//     <Recommendation>Validate file contains secrets, remove, roll credential, and use approved store. For additional information on secret remediation see https://aka.ms/credscan </Recommendation>
//     <Severity>3</Severity>
//   </ContentSearcher>


//   <ContentSearcher>
//     <Name>EncryptedPassword</Name>
//     <RuleId>CSCAN0200</RuleId>
//     <ResourceMatchPattern>\.ini$</ResourceMatchPattern>
//     <ContentSearchPatterns>
//       <string>[eE][nN][cC]_[uU][sS][eE][rR][nN][aA][mM][eE]=[\w]+[\r\n]+[eE][nN][cC]_[pP][aA][sS][sS][wW][oO][rR][dD]=[\w]+</string>
//     </ContentSearchPatterns>
//     <MatchDetails>Found DevDiv TFVC repo secrets.</MatchDetails>
//     <Recommendation>Validate file contains secrets, remove, roll credential, and use approved store. For additional information on secret remediation see https://aka.ms/credscan </Recommendation>
//     <Severity>2</Severity>
//     <GroupsExtractorClassName>Microsoft.Art.ContentSearch.EncodedUserNameExtractor, Microsoft.Art.ContentSearch</GroupsExtractorClassName>
//   </ContentSearcher>

// CSCAN0210 checks for Git repo credentials - covered elsewhere

// CSCAN0230 checks for Slack tokens - covered in slack.go

//   <ContentSearcher>
//     <Name>VstsPersonalAccessToken</Name>
//     <RuleId>CSCAN0240</RuleId>
//     <ResourceMatchPattern>\.(azure|bat|cmd|config|cpp|cs|cscfg|definitions|dtsx|ini|java|jsx?|json|keys|loadtest|m|md|php|properties|ps1|psm1|pubxml|py|resx|sample|sql|ste|test|tsx?|txt|waz|xml)$</ResourceMatchPattern>
//     <ContentSearchPatterns>
//       <string>([aA]ccess_?[tT]oken|ACCESS_?TOKEN).*?['="][a-z2-7]{52}('|"|\s|[\r\n]+)</string>
//       <string>[pP]ass[wW]ord\s+[a-z2-7]{52}(\s|[\r\n]+)</string>
//       <string>([aA]ccess_?[tT]oken|ACCESS_?TOKEN).*?[>|'|=|"][a-zA-Z0-9/+]{70}==</string>
//     </ContentSearchPatterns>
//     <MatchDetails>Found Vsts personal access token in source file.</MatchDetails>
//     <Recommendation>Validate file contains secrets, remove, roll credential, and use approved store. For additional information on secret remediation see https://aka.ms/credscan </Recommendation>
//     <Severity>3</Severity>
//     <SearchValidatorClassName>Microsoft.Art.ContentSearch.Base64EncodedVstsAccessTokenValidator, Microsoft.Art.ContentSearch</SearchValidatorClassName>
//   </ContentSearcher>

// CSCAN0250 - covered in jwt.go

//   <ContentSearcher>
//     <Name>AnsibleVault</Name>
//     <RuleId>CSCAN0260</RuleId>
//     <ResourceMatchPattern>\.yml$</ResourceMatchPattern>
//     <ContentSearchPatterns>
//       <string>\$ANSIBLE_VAULT;[0-9]\.[0-9];AES256[\r\n]+[0-9]+</string>
//     </ContentSearchPatterns>
//     <MatchDetails>Found ansible vault in source file.</MatchDetails>
//     <Recommendation>Validate file contains secrets, remove, roll credential, and use approved store. For additional information on secret remediation see https://aka.ms/credscan </Recommendation>
//     <Severity>3</Severity>
//   </ContentSearcher>
//   <ContentSearcher>
//     <Name>AzurePowerShellTokenCache</Name>
//     <RuleId>CSCAN0270</RuleId>
//     <ResourceMatchPattern>\.json$</ResourceMatchPattern>
//     <ContentSearchPatterns>
//       <string>["']TokenCache["']\s*:\s*\{\s*["']CacheData["']\s*:\s*["'][a-zA-Z0-9/\+]{86}</string>
//     </ContentSearchPatterns>
//     <MatchDetails>Found Azure Subscription Token Cache.</MatchDetails>
//     <Recommendation>Validate file contains secrets, remove, roll credential, and use approved store. For additional information on secret remediation see https://aka.ms/credscan </Recommendation>
//     <Severity>3</Severity>
//   </ContentSearcher>

