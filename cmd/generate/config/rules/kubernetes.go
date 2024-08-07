package rules

import (
	"fmt"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

// KubernetesSecret validates if we detected a kubernetes secret which contains data!
func KubernetesSecret() *config.Rule {

	//language=regexp
	kindPat := `\bkind:[ \t]*["']?secret["']?`
	//language=regexp
	dataPat := `\bdata:(?:.|\s){0,100}?\s+([\w.-]+:(?:[ \t]*(?:\||>[-+]?)\s+)?[ \t]*["']?[a-z0-9]+={0,2})["']?`

	// define rule
	r := config.Rule{
		RuleID:      "kubernetes-secret",
		Description: "Possible Kubernetes Secret detected, posing a risk of leaking credentials/tokens from your deployments",
		// We try to match secrets by looking if we have the keyword
		Regex: regexp.MustCompile(fmt.Sprintf(
			//language=regexp
			`(?i)(?:%s(?:.|\s){0,200}?%s|%s(?:.|\s){0,200}?%s)`, kindPat, dataPat, dataPat, kindPat)),
		Keywords: []string{
			"secret",
		},
		// Kubernetes secrets are always yaml files, we limit to common yaml-endings to make this rule more safe!
		Path: regexp.MustCompile(`(?i)\.ya?ml$`),
	}

	// validate
	tps := map[string]string{
		// Sample Kubernetes Secret from https://kubernetes.io/docs/concepts/configuration/secret/
		// The "data"-key is after the identifier "kind: Secret"
		"after-kubernetes.yaml":        "apiVersion: v1\nkind: secret\n data:\n extra: YmFyCg==\n metadata:\n name: secret-sa-sample\n annotations:\n kubernetes.io/service-account.name: 'sa-name'",                                                                                            // gitleaks:allow
		"after-kubernetes.yml":         "apiVersion: v1\nkind: Secret\n data:\n password: UyFCXCpkJHpEc2I9\n username: YWRtaW4=\n metadata:\n creationTimestamp: '2022-06-28T17:44:13Z'\n name: db-user-pass\n namespace: default\n type: Opaque",                                               // gitleaks:allow
		"after-comment.yml":            "apiVersion: v1\nkind: Secret\n metadata:\n creationTimestamp: '2022-06-28T17:44:13Z'\n name: db-user-pass\n namespace: default\n type: Opaque\ndata:\n  # the data is abbreviated in this example\n password: UyFCXCpkJHpEc2I9\n username: YWRtaW4=\n", // gitleaks:allow
		"after-quoted-1.yaml":          "apiVersion: v1\nkind: 'Secret'\n data:\n password: UyFCXCpkJHpEc2I9\n username: YWRtaW4=\n metadata:\n name: db-user-pass\n namespace: default\n type: Opaque",                                                                                         // gitleaks:allow
		"after-quoted-2.yaml":          "apiVersion: v1\nkind: 'secret'\n data:\n password: UyFCXCpkJHpEc2I9\n username: YWRtaW4=\n metadata:\n name: db-user-pass\n namespace: default\n type: Opaque",                                                                                         // gitleaks:allow
		"after-multiline-literal.yaml": "apiVersion: v1\nkind: Secret\nmetadata:\n  name: secret-dockercfg\ntype: kubernetes.io/dockercfg\ndata:\n  .dockercfg: |\n    eyJhdXRocyI6eyJodHRwczovL2V4YW1wbGUvdjEvIjp7ImF1dGgiOiJvcGVuc2VzYW1lIn19fQo=",
		"after-multiline-folded.yaml":  "apiVersion: v1\nkind: Secret\nmetadata:\n  name: secret-dockercfg\ntype: kubernetes.io/dockercfg\ndata:\n  .dockercfg: >\n    eyJhdXRocyI6eyJodHRwczovL2V4YW1wbGUvdjEvIjp7ImF1dGgiOiJvcGVuc2VzYW1lIn19fQo=",
		// The "data"-key is before the identifier "kind: Secret"
		"before-kubernetes.yaml":        "apiVersion: v1\n data:\n extra: YmFyCg==\n kind: secret\n metadata:\n name: secret-sa-sample\n annotations:\n kubernetes.io/service-account.name: 'sa-name'",                                                                                           // gitleaks:allow
		"before-kubernetes.yml":         "apiVersion: v1\n data:\n password: UyFCXCpkJHpEc2I9\n username: YWRtaW4=\n kind: Secret\n metadata:\n creationTimestamp: '2022-06-28T17:44:13Z'\n name: db-user-pass\n namespace: default\n type: Opaque",                                              // gitleaks:allow
		"before-comment.yml":            "apiVersion: v1\n data:\n  # the data is abbreviated in this example\n password: UyFCXCpkJHpEc2I9\n username: YWRtaW4=\n kind: Secret\n metadata:\n creationTimestamp: '2022-06-28T17:44:13Z'\n name: db-user-pass\n namespace: default\n type: Opaque", // gitleaks:allow
		"before-quoted-1.yaml":          "apiVersion: v1\n data:\n extra: YmFyCg==\n kind: 'Secret'\n metadata:\n name: 'secret-sa-sample'\n annotations:\n kubernetes.io/service-account.name: 'sa-name'",                                                                                       // gitleaks:allow
		"before-quoted-2.yaml":          "apiVersion: v1\n data:\n extra: YmFyCg==\n kind: 'secret'\n metadata:\n name: 'secret-sa-sample'\n annotations:\n kubernetes.io/service-account.name: 'sa-name'",                                                                                       // gitleaks:allow
		"before-multiline-literal.yaml": "apiVersion: v1\ndata:\n  .dockercfg: |\n    eyJhdXRocyI6eyJodHRwczovL2V4YW1wbGUvdjEvIjp7ImF1dGgiOiJvcGVuc2VzYW1lIn19fQo=\nmetadata:\n  name: secret-dockercfg\ntype: kubernetes.io/dockercfg\nkind: Secret",
		"before-multiline-folded.yaml":  "apiVersion: v1\ndata:\n  .dockercfg: >\n    eyJhdXRocyI6eyJodHRwczovL2V4YW1wbGUvdjEvIjp7ImF1dGgiOiJvcGVuc2VzYW1lIn19fQo=\nmetadata:\n  name: secret-dockercfg\ntype: kubernetes.io/dockercfg\nkind: Secret",
	}
	return validateWithPaths(r, tps, nil)
}
