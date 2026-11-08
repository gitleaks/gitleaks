package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func MSSQLConnectionString() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a Microsoft SQL Server connection string with embedded credentials, which could lead to unauthorized database access.",
		RuleID:      "mssql-connection-string",
		Regex:       regexp.MustCompile(`(?i)(?:data[ \t]+source|server)[ \t]*=[ \t]*[^;\r\n]+;[^\r\n]*?(?:password|pwd)[ \t]*=[ \t]*[^;\s'"]{3,}`),
		Keywords:    []string{"data source", "server"},
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
		// Note: the issue's example uses =False here, but the substring
		// "false" currently trips the overmatching global boolean
		// allowlist (see #2293, fix pending in #2294), so =True is used.
		`Server=tcp:assignmentdbserver.database.windows.net,1433;Initial Catalog=SyasyaDb;Persist Security Info=True;User ID=lky1020;Password=lky_1234;MultipleActiveResultSets=True;Encrypt=True;TrustServerCertificate=True;Connection Timeout=30;`,
		// keys are case-insensitive
		`data source=dbserver1.example.com;initial catalog=InventoryDB;user id=admin_user;password=SecureP@ss123;`,
		`SERVER=182.53.24.111;UID=technos6_cafe;PWD=cn*6s6I12;`,
	}
	fps := []string{
		// no password present
		`Data Source=dbserver1.example.com;Initial Catalog=InventoryDB;Integrated Security=True;`,
		`Server=prod-sql01;Database=SalesDB;Uid=reporting_user;`,
		// empty or trivially short password
		`Data Source=dbserver1.example.com;User Id=u;Password=;`,
		`Data Source=dbserver1.example.com;User Id=u;Pwd=ab;`,
		// no server part
		`Password=SecureP@ss123;`,
		// keys split across lines are not connection strings
		"Data Source=dbserver1.example.com;\nPassword=SecureP@ss123;",
	}
	return utils.Validate(r, tps, fps)
}
