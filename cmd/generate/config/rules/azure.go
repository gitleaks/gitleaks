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

// CSCAN0050, CSCAN0060, CSCAN0070 - covered in PrivateKey.go

// CSCAN0080 looks for 'Password' in XML file

func AzurePassword1() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0090 - Found Azure password, symmetric key or storage credential in source file. Validate file contains secrets, remove, roll credential, and use approved store.",
		RuleID:      "azure-password-1",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`AccountKey\s*=\s*MII[a-zA-Z0-9/+]{43,}?={0,2}`),
	}

	// validate
	tps := []string{
		generateSampleSecret("azure-password-1",
			"AccountKey = MII" + secrets.NewSecret(alphaNumeric("43"))),
	}
	return validate(r, tps, nil)
}


//   <ContentSearcher>
//     <Name>ConfigFile</Name>
//     <RuleId>CSCAN0090</RuleId>
//     <ResourceMatchPattern>\.(config|cscfg|conf|json|jsx?|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|tsx?|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|sh|m|php|py|xaml|keys|cmd|rds|loadtest|properties|vbs|ccf|user)$|(hubot|project.params)</ResourceMatchPattern>
//     <ContentSearchPatterns>
//       <string></string>
//       <string>(decryptionKey|validationKey)=&quot;[a-zA-Z0-9]+&quot;</string>
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




//     <Name>ScriptPassword</Name>
//     <RuleId>CSCAN0110</RuleId>
//     <ResourceMatchPattern>(\.cmd|\.ps|\.ps1|\.psm1)$</ResourceMatchPattern>
//     <ContentSearchPatterns>
//       <string>\s-([pP]ass[wW]ord|PASSWORD)\s+(&quot;[^&quot;\r\n]*&quot;|&apos;[^&apos;\r\n]*&apos;)</string>
//       <string>\s-([pP]ass[wW]ord|PASSWORD)\s+[^$\(\)\[\{&lt;\-\r\n]+\s*(\r\n|\-)</string>
//     </ContentSearchPatterns>
//     <MatchDetails>Found potential password in script file.</MatchDetails>
//     <Recommendation>Validate file contains secrets, remove, roll credential, and use approved store. For additional information on secret remediation see https://aka.ms/credscan </Recommendation>
//     <Severity>3</Severity>
//   </ContentSearcher>
//   <ContentSearcher>
//     <Name>GeneralPassword</Name>
//     <RuleId>CSCAN0111</RuleId>
//     <ResourceMatchPattern>\.(asax|ascx|aspx|bak|c|cmd|conf|cpp|cs|dart|dsql|hpp|html|idl|iis|ini|ja|java|jsx?|md|mef|omi|php|pl|pm|ps1|psm1|py|rb|resx|sh|shf|sql|svc|test|trx|tsx?|txt|vbs|xml)$</ResourceMatchPattern>
//     <ContentSearchPatterns>
//       <string>[a-zA-Z_\s](([pP]ass[wW]ord)PASSWORD|([cC]lient|CLIENT|[aA]pp|APP)_?([sS]ecret|SECRET))\s{0,3}=\s{0,3}['"][^\s"']{2,200}?['"][;\s]</string>
//     </ContentSearchPatterns>
//     <ContentSearchFilters>
//       <ContentFilter>
//         <Name>FalsePositiveCases</Name>
//         <Filters>
//           <string>['"](yes|no|true|false)['"]</string>
//           <string>placeholder</string>
//           <string>['"](?&lt;c>.)\k&lt;c>{3,}</string>
//           <string>\s\+\s</string>
//           <string>['"][%\$#@].*[%\$#@]?['"]</string>
//           <string>['"]\$?[\{\(\[\&lt;].*[\}\)\]\>]['"]</string>
//           <string>['"]\$\d['"]</string>
//           <string>['"]\s?([^\s'"]+?\s)+([^\s'"]+?)?['"]</string>
//           <string>['"]\s+['"]</string>
//           <string>['"]\\0['"]</string>
//           <string>\{\d\}</string>
//           <string>-1</string>
//           <string>vault|param|attribute|any|['"]\"['"]|foo|bar|fake|example|here|invalid|\*\*\*</string>
//         </Filters>
//       </ContentFilter>
//     </ContentSearchFilters>
//     <MatchDetails>Found potential password in script file.</MatchDetails>
//     <Recommendation>Validate file contains secrets, remove, roll credential, and use approved store. For additional information on secret remediation see https://aka.ms/credscan </Recommendation>
//     <Severity>3</Severity>
//   </ContentSearcher>
//   <ContentSearcher>
//     <Name>ExternalApiSecret</Name>
//     <RuleId>CSCAN0120</RuleId>
//     <ResourceMatchPattern>\.cs$|\.cpp$|\.c$</ResourceMatchPattern>
//     <ContentSearchPatterns>
//       <string>private\sconst\sstring\s[aA]ccessTokenSecret\s=\s".*";</string>
//       <string>private\sconst\sstring\s[aA]ccessToken\s=\s".*";</string>
//       <string>private\sconst\sstring\s[cC]onsumerSecret\s=\s".*";</string>
//       <string>private\sconst\sstring\s[cC]onsumerKey\s=\s".*";</string>
//       <string>FacebookClient\([pP]ageAccessToken\);</string>
//       <string>[pP]ageAccessToken\s=\s".*";</string>
//       <string>private\sstring\s[tT]wilioAccountSid\s=\s".*";</string>
//       <string>private\sstring\s[tT]wilioAuthToken\s=\s".*";</string>
//     </ContentSearchPatterns>
//     <MatchDetails>Found potential external API secret in source file.</MatchDetails>
//     <Recommendation>Validate file contains secrets, remove, roll credential, and use approved store. For additional information on secret remediation see https://aka.ms/credscan </Recommendation>
//     <Severity>3</Severity>
//   </ContentSearcher>
//   <ContentSearcher>
//     <Name>MonitoringAgent</Name>
//     <RuleId>CSCAN0130</RuleId>
//     <ResourceMatchPattern>AgentConfig\.xml$</ResourceMatchPattern>
//     <ContentSearchPatterns>
//       <string>Account moniker\s?=.*key\s?=.*</string>
//     </ContentSearchPatterns>
//     <ContentSearchFilters>
//       <ContentFilter>
//         <Name>Auto Key Patterns ContentFilters</Name>
//         <Filters>
//           <string>autoKey</string>
//           <string>%s</string>
//         </Filters>
//       </ContentFilter>
//     </ContentSearchFilters>
//     <MatchDetails>Found storage credential in MonitoringAgent config file.</MatchDetails>
//     <Recommendation>Validate file contains secrets, remove, roll credential, and use approved store. For additional information on secret remediation see https://aka.ms/credscan </Recommendation>
//     <Severity>3</Severity>
//   </ContentSearcher>
//   <ContentSearcher>
//     <Name>DefaultPassword</Name>
//     <RuleId>CSCAN0140</RuleId>
//     <ResourceMatchPattern>\.(cs|xml|config|json|tsx?|cfg|txt|ps1|bat|cscfg|rdg|linq|publishsettings|cmd|psm1|aspx|asmx|vbs|added_cluster|clean|pubxml|ccf|ini|svd|sql|c|xslt|csv|FF|ExtendedTests|settings|cshtml|template|trd|argfile|scala|pbix)$|(config|certificate|publish|UT)\.js$|(commands|user|tests)\.cpp$</ResourceMatchPattern>
//     <ContentSearchPatterns>
//       <string>T!T@n1130|[pP]0rsche911|[cC]o[mM][mM]ac\!12|[pP][aA]ss@[wW]or[dD]1|[rR]dP[aA]\$\$[wW]0r[dD]|iis6\!dfu|[pP]@ss[wW]or[dD]1|[pP][aA]\$\$[wW]or[dD]1|\!\!123ab|[aA]dmin123|[pP]@ss[wW]0r[dD]1|[uU]ser@123|[aA]bc@123|[pP][aA]ss[wW]or[dD]@123|[rR]dP@\$\$[wW]0r[dD]|homerrocks|[pP][aA]\$\$[wW]0r[dD]1?|\![pP][aA]sswor[dD]1|[pP][aA]55[wW]or[dD]1|[pP]@\$\$[wW]0r[dD]1|[pP][aA]ss[wW]0r[dD]1|[jJ]\$p1ter|[rR]dP[aA]ss[wW]0r[dD]|Y29NbWFjITEy|[pP][aA]ss4Sales|[rR]dPa\$\$[wW]or[dD]|\![pP]@ss[wW]0r[dD]1|WS2012R2R0cks\!|DSFS0319Test|March2010M2\!|[pP][aA]ss[wW]ord~1|UL0brlXlp_r8vG6iiRvCcsFDfu6bJ6KK|7\-Tdh3Klrec4dJbOyONDOkCQ84BWN1JN|\$mCertPwd|[pP][aA]\$\$[wW]or[dD]!|2012\$erver!|2008\$erver!|#Bugsfor\$|ITG2Install!|[rR]dP[aA]\$\$[wW]0r[dD]|T!T@n113000|T!T@n1130T!T@n1130|TitanP[wW][dD]%|ChocoCheese!|n1130@T!T|[mM]icr0s0ft|test1test!|123@tieorg|IWantYouToTripLikeIDo!\?|homerocks|[eE]lvis1|S_MSLocal~!@#|([uU]ser|USER)@123</string>
//     </ContentSearchPatterns>
//     <MatchDetails>Found known password in source file.</MatchDetails>
//     <Recommendation>Validate file contains secrets, remove, roll credential, and use approved store. For additional information on secret remediation see https://aka.ms/credscan </Recommendation>
//     <Severity>3</Severity>
//   </ContentSearcher>
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
//     <ContentSearchFilters>
//       <ContentFilter>
//         <Name>Key Patterns ContentFilters</Name>
//         <Filters>
//           <string>AccountKey\s*=\s*MII[a-zA-Z0-9/+]{43,}={0,2}</string>
//           <string>=(?&lt;c>.)\k&lt;c>{3,}</string>
//           <string>(password|pwd)=&lt;[a-z0-9]+></string>
//         </Filters>
//       </ContentFilter>
//     </ContentSearchFilters>
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
//   <ContentSearcher>
//     <Name>GitCredential</Name>
//     <RuleId>CSCAN0210</RuleId>
//     <ResourceMatchPattern>\.gitCredentials$</ResourceMatchPattern>
//     <ContentSearchPatterns>
//       <string>[hH][tT][tT][pP][sS]?://.+:.+@\[^/].[cC][oO][mM]</string>
//     </ContentSearchPatterns>
//     <MatchDetails>Found Git repo credentials.</MatchDetails>
//     <Recommendation>Validate file contains secrets, remove, roll credential, and use approved store. For additional information on secret remediation see https://aka.ms/credscan </Recommendation>
//     <Severity>2</Severity>
//   </ContentSearcher>
//   <ContentSearcher>
//     <Name>DefaultPasswordContexts</Name>
//     <RuleId>CSCAN0220</RuleId>
//     <ResourceMatchPattern>\.(cs|xml|config|json|tsx?|cfg|txt|ps1|bat|cscfg|publishsettings|cmd|psm1|aspx|asmx|vbs|added_cluster|clean|pubxml|ccf|ini|svd|sql|c|xslt|csv|FF|ExtendedTests|settings|cshtml|template|trd|argfile|scala|rdg|linq|hql|go|rs|pl|java|php|py|vb)$|(config|certificate|publish|UT)\.js$|(commands|user|tests)\.cpp$</ResourceMatchPattern>
//     <ContentSearchPatterns>
//       <string>[cC]onvert[tT]o-[sS]ecure[sS]tring(\s*-[sS]tring)?\s*"(?&lt;scoringvalue&gt;[^"\r\n]+)"</string>
//       <string>new\sX509Certificate2\([^()]*,\s*"(?&lt;scoringvalue&gt;[^"\r\n]+)"[^)]*\)</string>
//       <string>&lt;[pP]ass[wW]ord&gt;(&lt;[vV]alue&gt;)?(?&lt;scoringvalue&gt;.+)(&lt;/[vV]alue&gt;)?&lt;/[pP]ass[wW]ord&gt;</string>
//       <string>([cC]lear[tT]ext[pP]ass[wW]ord|CLEARTEXTPASSWORD)(")?\s*[:=]\s*"(?&lt;scoringvalue&gt;[^"\r\n]+)"</string>
//       <string>[cC]ert[uU]til(.exe)?\s+(\-[a-zA-Z]+\s+)*\-[pP]\s+(?&lt;quote&gt;["'])(?&lt;scoringvalue&gt;[^"'%]+)\k&lt;quote&gt;</string>
//       <string>[cC]ert[uU]til(.exe)?\s+(\-[a-zA-Z]+\s+)*\-[pP]\s+(?&lt;scoringvalue&gt;[^"']\S*)\s</string>
//       <string>([pP]ass[wW]ord|PASSWORD)\s*=\s*[nN]?(?&lt;quote&gt;["'])(?&lt;scoringvalue&gt;[^"'\r\n]{4,})\k&lt;quote&gt;</string>
//     </ContentSearchPatterns>
//     <ContentSearchFilters>
//       <ContentFilter>
//         <Name>DefaultPasswordContexts Content Filter</Name>
//         <Filters>
//           <string>&lt;value&gt;&lt;/value&gt;</string>
//           <string>['"]\$?[\{\(\[\&lt;].*[\}\)\]\>]['"]</string>
//         </Filters>
//       </ContentFilter>
//     </ContentSearchFilters>
//     <MatchDetails>Found known password context with password in source file.</MatchDetails>
//     <Recommendation>Validate file contains secrets, remove, roll credential, and use approved store. For additional information on secret remediation see https://aka.ms/credscan </Recommendation>
//     <Severity>3</Severity>
//     <SearchValidatorClassName>Microsoft.Art.ContentSearch.PasswordContextValidator, Microsoft.Art.ContentSearch</SearchValidatorClassName>
//   </ContentSearcher>
//   <ContentSearcher>
//     <Name>SlackToken</Name>
//     <RuleId>CSCAN0230</RuleId>
//     <ResourceMatchPattern>\.(ps1|psm1|jsx?|tsx?|json|coffee|xml|md|html|py|php|java|ipynb|rb|scala)$|hubot</ResourceMatchPattern>
//     <ContentSearchPatterns>
//       <string>xoxp-[a-zA-Z0-9]+-[a-zA-Z0-9]+-[a-zA-Z0-9]+-[a-zA-Z0-9]+</string>
//       <string>xoxb-[a-zA-Z0-9]+-[a-zA-Z0-9]+</string>
//     </ContentSearchPatterns>
//     <MatchDetails>Found slack token in source file.</MatchDetails>
//     <Recommendation>Validate file contains secrets, remove, roll credential, and use approved store. For additional information on secret remediation see https://aka.ms/credscan </Recommendation>
//     <Severity>3</Severity>
//   </ContentSearcher>
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

