package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func MSSQLConnectionString() *config.Rule {
	// Single-line SQL Server credential strings: ADO.NET key/value pairs
	// in either key order, JDBC sqlserver URLs, and mssql:// URIs with
	// userinfo (SQLAlchemy dialects). ADO.NET server keys are Data Source,
	// Server, Network Address (bare Address/Addr excluded: they match
	// code identifiers and prose and span kilobytes to a distant
	// password, measured 66KB findings on minified JS bundles). Bare
	// passwords need 3+ chars; quoted values match when non-empty. See
	// the PR body for the full rationale.
	r := config.Rule{
		Description: "Discovered a Microsoft SQL Server connection string with embedded credentials, which could lead to unauthorized database access.",
		RuleID:      "mssql-connection-string",
		Regex:       regexp.MustCompile(`(?i)(?:\b(?:data source|network address|server)[ \t\x{00A0}]*=[ \t\x{00A0}]*[^;\r\n]*[^;\r\n\s'"][^;\r\n]*;[^\r\n]*?\b(?:password|pwd)[ \t\x{00A0}]*=[ \t\x{00A0}]*(?:'(?:[^'\r\n]|'')+'|"(?:[^"\r\n]|"")+"|[^;\s'"]{3}[^;\r\n'"]*|'[^';\r\n]{3,}|"[^";\r\n]{3,}|[^;\s'"][^;'"]{2,}[^;\s'"])|\b(?:password|pwd)[ \t\x{00A0}]*=[ \t\x{00A0}]*(?:'(?:[^'\r\n]|'')+'|"(?:[^"\r\n]|"")+"|[^;\s'"]{3}|'[^';\r\n]{3,}|"[^";\r\n]{3,}|[^;\s'"][^;'"]{2,}[^;\s'"])[^;\r\n]*;[^\r\n]*?\b(?:data source|network address|server)[ \t\x{00A0}]*=[ \t\x{00A0}]*[^;\r\n]*[^;\r\n\s'"][^;\r\n]*|\bjdbc:(?:jtds:)?sqlserver://[^;\r\n]*[^;\r\n\s\'"][^;\r\n]*;[^\r\n]*?\b(?:password|pwd)[ \t\x{00A0}]*=[ \t\x{00A0}]*(?:'(?:[^'\r\n]|'')+'|"(?:[^"\r\n]|"")+"|[^;\s'"]{3}[^;\r\n'"]*|'[^';\r\n]{3,}|"[^";\r\n]{3,}|[^;\s'"][^;'"]{2,}[^;\s'"])|\bmssql(?:\+[a-z0-9_.-]+)?://(?:[^/\s:@;]+@)?[^/\s:@;]+:[^/@\s;]{3,}@[^/\s;]+)`),
		Keywords:    []string{"data source", "server", "network address", "jdbc:sqlserver", "jdbc:jtds", "mssql"},
		Allowlists: []*config.Allowlist{
			{
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`(?i)(?:^|;)(?:\s|\x{00A0})*(?:password|pwd)(?:\s|\x{00A0})*=(?:\s|\x{00A0})*['"\x60]?(?:change(?:it|[-_]?me)|pass(?:word)?|pwd|null|nil|none|undefined|todo|fixme|test|token|\*+|x+|\.+|\?+)['"\x60]?(?:\s|\x{00A0})*(?:;|$)`),                                                                                                                                                                                                     // literal placeholders and masks, password slot only
					regexp.MustCompile(`(?i)(?:^|;)(?:\s|\x{00A0})*(?:password|pwd)(?:\s|\x{00A0})*=(?:\s|\x{00A0})*['"\x60]?(?:<[^>]*>|\[[^]]*\]|\$\{[^}]*\}|\$(?:(?-i:[A-Z][A-Z0-9_]*)|[0-9]|[_@*#?$!$-])|\$\([^)]*\)|\{\{[^}]*\}\}|\{[A-Za-z0-9_.]*[._][A-Za-z0-9_.]*\}|(?-i:\{[a-z]+\}|\{[A-Z][A-Z0-9_]*\})|\{[0-9]+\}|\{\}|%[^%]+%)['"\x60]?(?:\s|\x{00A0})*(?:;|$)`),                                                                                                 // $VAR/${}/$()/{{}}/{}/<>/[]/%VAR% templates, password slot only
					regexp.MustCompile(`(?i)(?:^|;)(?:\s|\x{00A0})*(?:password|pwd)(?:\s|\x{00A0})*=(?:\s|\x{00A0})*['"\x60]?(?-i:[A-Z0-9_]*_(?:PASSWORD|PWD)(?:_[A-Z0-9_]+)?|(?:PASSWORD|PWD)_[A-Z0-9_]+)['"\x60]?(?:\s|\x{00A0})*(?:;|$)`),                                                                                                                                                                                                                               // SCREAMING_SNAKE placeholders (case-sensitive)
					regexp.MustCompile(`(?i)://(?:[^/:@\s;]+@)?[^/:@\s;]+:(?:change(?:it|[-_]?me)|pass(?:word)?|pwd|null|nil|none|undefined|todo|fixme|test|token|\*+|x+|\.+|\?+|<[^>]*>|\[[^]]*\]|\$\{[^}]*\}|\$(?:(?-i:[A-Z][A-Z0-9_]*)|[0-9]|[_@*#?$!$-])|\$\([^)]*\)|\{\{[^}]*\}\}|\{[A-Za-z0-9_.]*[._][A-Za-z0-9_.]*\}|(?-i:\{[a-z]+\}|\{[A-Z][A-Z0-9_]*\})|\{[0-9]+\}|\{\}|%[^%]+%|(?-i:[A-Z0-9_]*_(?:PASSWORD|PWD)(?:_[A-Z0-9_]+)?|(?:PASSWORD|PWD)_[A-Z0-9_]+))@`), // same placeholder sets for mssql:// userinfo
				},
			},
		},
	}

	// validate
	tps := []string{
		// examples from https://github.com/gitleaks/gitleaks/issues/1715
		`Data Source=dbserver1.example.com;Initial Catalog=InventoryDB;User Id=admin_user;Password=SecureP@ss123;`,
		`Data Source=prod-sql01.mycompany.net;Initial Catalog=SalesDB;User Id=reporting_user;Password=P@ssword789;Encrypt=True;TrustServerCertificate=True;`,
		`Data Source=analytics-db03.example.net;Initial Catalog=AnalyticsDB;User Id=analytics_user;Password=4nalyt!cs@Work;MultipleActiveResultSets=True;`,
		`Data Source=secure-sql.example.net;Initial Catalog=CustomerDB;Uid=customer_user;Pwd=CustP@ss123;Encrypt=True;TrustServerCertificate=True;`,
		`Data Source=analytics-node.example.org,1533;Initial Catalog=AnalyticsDB;Uid=analytics_user;Pwd=An@lytics789;`,
		`Data Source=prod-cluster\ReportingInstance;Initial Catalog=ReportsDB;Uid=report_user;Pwd=R3port!Secure;`,
		`@"Data Source=n9lxnyuzhv.database.windows.net; Authentication=Active Directory Password; Initial Catalog=testdb;  UID=bob@contoso.onmicrosoft.com; PWD=MyPassWord!";`,
		`Server=182.53.24.111;Initial Catalog=technos6_cafe;User ID=technos6_cafe;Password=cn*6s6I12;TrustServerCertificate=True`,
		// Byte-exact from the issue except Persist Security Info: the
		// issue's =False sits inside the match span and trips the
		// overmatching global boolean allowlist (see #2293, fix pending
		// in #2294), so =True is used there. The post-password =False
		// keys sit past the span end and pin that behavior.
		`Server=tcp:assignmentdbserver.database.windows.net,1433;Initial Catalog=SyasyaDb;Persist Security Info=True;User ID=lky1020;Password=lky_1234;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;`,
		// keys are case-insensitive
		`data source=dbserver1.example.com;initial catalog=InventoryDB;user id=admin_user;password=SecureP@ss123;`,
		`SERVER=182.53.24.111;UID=technos6_cafe;PWD=cn*6s6I12;`,
		// password-first orders (ADO.NET accepts any key order)
		`Password=SecureP@ss123;Data Source=dbserver1.example.com;Initial Catalog=InventoryDB;`,
		`Password=P@ssword789;Encrypt=True;TrustServerCertificate=True;Data Source=prod-sql01.mycompany.net`,
		`Pwd=CustP@ss123;Server=182.53.24.111;`,
		`PWD=An@lytics789;MultipleActiveResultSets=True;SERVER=sql.example.com,1433;`,
		`Password=4nalyt!cs@Work;Initial Catalog=AnalyticsDB;User Id=u;Server=tcp:db.windows.net,1433;Connection Timeout=30;`,
		`password=a1!;data source=db;`,
		`Pwd=xYz789;Uid=admin;Data Source=db;`,
		// passwords may contain '=' (e.g. base64 padding)
		`Password=c2VjcmV0MTIzPQ==;Server=db.example.com;`,
		`Server=db.example.com;Password=secret==;`,
		// Network Address synonym, both orders
		`Network Address=db.example.com;User Id=u;Password=SecureP@ss123;`,
		`Password=Secret123;Network Address=db.example.com;`,
		// quoted passwords, the only legal spelling for ';' values
		`Server=db.example.com;Password='pa;ss;word';`,
		`Server=db.example.com;Password="pa;ss;word";`,
		`Password='pa;ss';Data Source=db.example.com;`,
		`Server=db;Password=' Secret123 ';`,
		`Server=db;Pwd='x7!';`,
		// doubled-quote escapes match in full, including leading ones
		// (a leading literal quote is spelled with three quotes)
		`Server=db;Password='a''b1234';`,
		`Server=db;Password='''leading';`,
		// same escapes, password-first and double-quoted
		`Password="pa;ss";Data Source=db;`,
		`Password='''leading';Server=db;`,
		`Password="""leading";Server=db;`,
		`Server=db;Password="""leading";`,
		// first credentialed slot wins: a later placeholder cannot hide
		// an earlier real password (first match decides)
		`Server=db;Password=good123;Password=xxx;`,
		`Password=good1;Server=x;Password=xxx;Server=db;`,
		// lowercase shapes fire: indistinguishable from human passwords
		`Server=db;Password=your_password;`,
		`Server=db;Password=$dbpass;`,
		// NBSP around '=' (Confluence-paste; .NET trims U+00A0)
		"Server\u00a0=\u00a0db;Password=p@ssw0rd!;",
		// spaces past the 3-char head are part of the value
		`Server=db;Password=mypass 123456;`,
		`Server=db;Password=abc def;`,
		// narrowness pins: affixed lookalikes are still real enough to flag
		`Server=db;Password=password123;`,
		`Server=db;Password=Passw0rd!;`,
		`Server=db;Password=undefined_behavior9;`,
		// ODBC-braced real secrets: mixed-case alnum is not a placeholder
		`Server=db;Pwd={S3cret123};`,
		`Server=db;Pwd={aB1};`,
		// unterminated quotes run to the separator (truncated lines)
		`Server=db;Password='real;`,
		`Password='real;Server=db;`,
		`Server=db;Password="real;`,
		// unquoted values may hold spaces past a non-space start
		`Server=db.example.com;Password=my pass 99;`,
		`Server=db.example.com;Password=a b c 99;`,
		`Password=a b c 99;Server=db;`,
		// JDBC sqlserver URLs carry ;password= props after the host
		`jdbc:sqlserver://db.example.com:1433;databaseName=mydb;user=sa;password=S3cr3t!Pass9;`,
		`jdbc:sqlserver://192.168.1.50:1433;database=mydb;user=dbuser;password=S3cr3t!Pass9;encrypt=true;`,
		`jdbc:sqlserver://db;password=R3al!x;encrypt=true;trustServerCertificate=false;`,
		`jdbc:jtds:sqlserver://db;password=S3cret9!x;`,
		`jdbc:jtds:sqlserver://db:1433;database=x;user=u;password=R3al!x;`,
		// SQLAlchemy mssql URIs carry user:password@ userinfo
		`mssql+pyodbc://sa:S3cr3t!Pass9@db.example.com/mydb?driver=ODBC+Driver+18+for+SQL+Server`,
		`mssql+pymssql://sa:S3cr3t!Pass9@db.example.com:1433/mydb`,
		`mssql+pyodbc://app_user:Pss:w0rd!@db/mydb`,
		`mssql+pyodbc://app_user:P%40ssw0rd@db/mydb`,
		`mssql+pyodbc://sa:{S3cret9}@host/db`,
		`mssql+pyodbc://user@domain.com:S3cret9!x@host/db`,
	}
	fps := []string{
		// no password present
		`Data Source=dbserver1.example.com;Initial Catalog=InventoryDB;Integrated Security=True;`,
		`Server=prod-sql01;Database=SalesDB;Uid=reporting_user;`,
		// empty or trivially short password
		`Data Source=dbserver1.example.com;User Id=u;Password=;`,
		`Data Source=dbserver1.example.com;User Id=u;Pwd=ab;`,
		`Password=ab;Data Source=dbserver;`,
		`Pwd=;Server=db;`,
		`Pwd=ab;Server=x`,
		// no server part
		`Password=SecureP@ss123;`,
		`Password=SecureP@ss123;Initial Catalog=InventoryDB;`,
		// empty or blank server value
		`Server=;Password=abcd1234;`,
		`Data Source=;Password=abcd1234;`,
		`Server=   ;Password=abcd1234;`,
		`Server='';Password=xxx12345;`,
		// keys buried in longer words are not ADO.NET keys
		`MyServer=db;Password=Secret123;`,
		`Server=db;MyPassword=Secret123;`,
		`Server=db;old_password=Secret123;`,
		`Apwd=Secret123;Server=db;`,
		`Password=Secret123;MyServer=db;`,
		// bare head rejects quotes and spaces in the first three chars
		`Server=db;Password=ab'cd;`,
		`Password=ab'cd;Server=db;`,
		`Server=db;Password=a b;`,
		`Password=a b;Server=db;`,
		// server values cannot start at a separator
		`Server=;foo;Password=good12;`,
		`Password=good12;Server=;foo;`,
		// placeholder passwords
		`Server=db;Password=password;`,
		`Server=db;Password=changeme;`,
		`Server=db;Password=xxx;`,
		`Server=db;Password=***;`,
		`Server=db;Password=...;`,
		`Server=db;Password=$DBPASS;`,
		`Server=db;Password='$9';`,
		`Server=db;Password='$$';`,
		`Server=${DB_HOST};Password=${DB_PASS};`,
		`Server=db;Password={pwd};`,
		`Server=db;Password={{vault_pass}};`,
		`Server=db;Password=<password>;`,
		`Server=db;Password=[secret];`,
		`Server=db;Password=REPLACE_WITH_PASSWORD;`,
		`Server=db;Password=YOUR_PASSWORD;`,
		// same placeholders, password-first (^ side of the slot anchor)
		`Password=password;Server=db;`,
		`Password=$DBPASS;Server=db;`,
		`Password=YOUR_PASSWORD;Server=db;`,
		// every literal in the set, pinned
		`Server=db;Password=test;`,
		`Server=db;Password=token;`,
		`Server=db;Password=pwd;`,
		`Server=db;Password=pass;`,
		`Server=db;Password=changeit;`,
		`Server=db;Password=$(DB_PASS);`,
		`Server=db;Password=%DB_PASS%;`,
		`Server=db;Password=PASSWORD_FOO;`,
		`Server=db;Password=MY_PWD;`,
		`Server=db;Password=MY_PASSWORD_X1;`,
		`Server=db;Password=PWD_BAR;`,
		// empty quoted passwords, both orders (rule floor, not allowlist)
		`Server=db;Password='';`,
		`Password='';Server=db;`,
		`Server=db;Password="";`,
		`Password="";Server=db;`,
		// language-nulls and author-notes are placeholders, not secrets
		`Server=db;Password=null;`,
		`Server=db;Password=nil;`,
		`Server=db;Password=none;`,
		`Server=db;Password=undefined;`,
		`Server=db;Password=todo;`,
		`Server=db;Password=fixme;`,
		`Server=db;Password=change-me;`,
		`Server=db;Password=???;`,
		"Server=db;Password=`test`;",
		// NBSP-padded placeholders suppress like space-padded ones
		"Server=db;Password=\u00a0test\u00a0;",
		"Server=db;Password\u00a0=\u00a0test;",
		// braced placeholder shapes still suppress after narrowing
		`Server=db;Password={0};`,
		`Server=db;Password={};`,
		`Server=db;Password='{}';`,
		`Server=db;Password={vault.pass};`,
		`Server=db;Password={DB_PASS};`,
		`Server=db;Password=Change_Me;`,
		// bare Address/Addr are out of scope: they match prose and code
		// identifiers (address=computeAddress(...)) and span kilobytes to
		// a distant password (66KB finding seen on ethers.js bundles);
		// the Data Source/Server/Network Address synonyms cover real
		// connection strings without that precision cost
		`Addr=db;Pwd=xxx12345;`,
		`Address=db.example.com,1433;User Id=u;Password=SecureP@ss123;`,
		`Addr=;Password=abcd1234;`,
		`Address=   ;Password=abcd1234;`,
		`MyAddress=db;Password=Secret123;`,
		`Readdress=db;Password=Secret123;`,
		// unterminated quotes keep the 3-char floor; placeholders suppress
		`Password='ab;Server=db;`,
		`Server=db;Password='test;`,
		`Password='test;Server=db;`,
		// JDBC shapes without a real password
		`jdbc:sqlserver://db:1433;databaseName=x;user=sa;password=test;`,
		`jdbc:sqlserver://db;user=sa;`,
		`jdbc:sqlserver://;password=Secret123;`,
		`jdbc:jtds:sqlserver://db;user=u;password=test;`,
		// URI shapes without a real password, plus a wrong scheme
		`mssql+pyodbc://sa:test@host/db`,
		`mssql+pymssql://user:PASSWORD@h/db`,
		`mssql+pyodbc://sa:${DB_PASS}@host/db`,
		`mssql+pyodbc://sa:YOUR_PWD@host/db`,
		`mssql+pyodbc://sa:ab@host/db`,
		`mssql+pyodbc://sa@host/db`,
		`mssql+pyodbc://sa:{db_pass}@host/db`,
		`mssql+pyodbc://user@domain.com:test@host/db`,
		`mssql+pyodbc://user@domain.com@host/db`,
		`postgresql://sa:S3cr3t!Pass9@host/db`,
		// KNOWN LIMITATION, pinned: a placeholder in the first password
		// slot hides a real secret in a later slot (single-pass match +
		// substring allowlist). Greedy gaps were measured and are worse:
		// the longer span still contains the placeholder and suppresses
		// the whole finding, while real-first lines regress. Fixing this
		// needs a second engine pass, which is upstream scope.
		`Server=db01;User Id=sa;Password=test;Foo=bar;Password=Real99!x;`,
		`Password=test;X=1;Server=db;Password=Real99!x;`,
		// keys split across lines are not connection strings
		"Data Source=dbserver1.example.com;\nPassword=SecureP@ss123;",
		"Password=SecureP@ss123;\nData Source=db;",
	}
	return utils.Validate(r, tps, fps)
}
