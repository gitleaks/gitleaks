package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

// The kubernetes rules are split into two functions to make the complex proximity matching of the data-key and the kind-identifier more readable and testable

// KubernetesSecretWithDataBefore validates if we detected a kubernetes secret which contains data, before the resource identifier!
func KubernetesSecretWithDataBefore() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "kubernetes-secret-with-data-before",
		Description: "Possible Kubernetes Secret detected, posing a risk of leaking credentials/tokens from your deployments",
		// We try to match secrets by looking if we have the keyword
		Regex: utils.GenerateUniqueTokenRegex(`(?i)(?:\b(?:data:))(\W+(?:\w+\W+){0,200}?)\bkind:.{0,10}Secret\b`, true),

		Keywords: []string{
			"Secret",
		},
		// Kubernetes secrets are always yaml files, we limit to common yaml-endings to make this rule more safe!
		Path: regexp.MustCompile(`(?i)\.ya?ml$`),
	}

	// validate
	tps := map[string]string{
		// Sample Kubernetes Secret from https://kubernetes.io/docs/concepts/configuration/secret/
		// These secrets contain the "data"-key before the actual identifier "kind: Secret"
		"kubernetes.yaml": "apiVersion: v1'\n' data:'\n' extra: YmFyCg=='\n' kind: secret'\n' metadata:'\n' name: secret-sa-sample'\n' annotations:'\n' kubernetes.io/service-account.name: 'sa-name'",                                                  // gitleaks:allow
		"kubernetes.yml":  "apiVersion: v1'\n' data:'\n' password: UyFCXCpkJHpEc2I9'\n' username: YWRtaW4='\n' kind: Secret'\n' metadata:'\n' creationTimestamp: '2022-06-28T17:44:13Z''\n' name: db-user-pass'\n' namespace: default'\n' type: Opaque", // gitleaks:allow
		// Quoted Test Cases
		"kubernetes-quoted-1.yaml": "apiVersion: v1'\n' data:'\n' extra: YmFyCg=='\n' kind: 'Secret''\n' metadata:'\n' name: 'secret-sa-sample''\n' annotations:'\n' kubernetes.io/service-account.name: 'sa-name'", // gitleaks:allow
		"kubernetes-quoted-2.yaml": "apiVersion: v1'\n' data:'\n' extra: YmFyCg=='\n' kind: 'secret''\n' metadata:'\n' name: 'secret-sa-sample''\n' annotations:'\n' kubernetes.io/service-account.name: 'sa-name'", // gitleaks:allow
	}
	return utils.ValidateWithPaths(r, tps, nil)
}

// KubernetesSecretWithDataAfter validates if we detected a kubernetes secret which contains data, after the resource identifier!
func KubernetesSecretWithDataAfter() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "kubernetes-secret-with-data-after",
		Description: "Possible Kubernetes Secret detected, posing a risk of leaking credentials/tokens from your deployments",
		// We try to match secrets by looking if we have the keyword
		Regex: utils.GenerateUniqueTokenRegex(`(?i)(?:\bkind:.{0,10}Secret\b)(?:.|\s){0,200}?\b(?:data:)\s*(.+)`, true),

		Keywords: []string{
			"Secret",
		},
		// Kubernetes secrets are always yaml files, we limit to common yaml-endings to make this rule more safe!
		Path: regexp.MustCompile(`(?i)\.ya?ml$`),
	}

	// validate
	tps := map[string]string{
		// Sample Kubernetes Secret from https://kubernetes.io/docs/concepts/configuration/secret/
		// These secrets contain the data after the  actual identifier "kind: Secret"
		"kubernetes.yaml": "apiVersion: v1'\n' kind: secret'\n' data:'\n' extra: YmFyCg=='\n' metadata:'\n' name: secret-sa-sample'\n' annotations:'\n' kubernetes.io/service-account.name: 'sa-name'",                                                  // gitleaks:allow
		"kubernetes.yml":  "apiVersion: v1'\n' kind: Secret'\n' data:'\n' password: UyFCXCpkJHpEc2I9'\n' username: YWRtaW4='\n' metadata:'\n' creationTimestamp: '2022-06-28T17:44:13Z''\n' name: db-user-pass'\n' namespace: default'\n' type: Opaque", // gitleaks:allow
		// Quoted Test Cases
		"kubernetes-quoted-1.yaml": "apiVersion: v1'\n' kind: 'Secret''\n' data:'\n' password: UyFCXCpkJHpEc2I9'\n' username: YWRtaW4='\n' metadata:'\n' name: db-user-pass'\n' namespace: default'\n' type: Opaque", // gitleaks:allow
		"kubernetes-quoted-2.yaml": "apiVersion: v1'\n' kind: 'secret''\n' data:'\n' password: UyFCXCpkJHpEc2I9'\n' username: YWRtaW4='\n' metadata:'\n' name: db-user-pass'\n' namespace: default'\n' type: Opaque", // gitleaks:allow
	}

	return utils.ValidateWithPaths(r, tps, nil)
}
