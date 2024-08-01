package rules

import (
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
		Regex: generateUniqueTokenRegex(`(?i)(?:\b(data)\b)\W+(?:\w+\W+){0,200}?\bkind:\s*Secret\b.*`, true),

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
		"kubernetes.yaml": "apiVersion: v1 data: extra: YmFyCg== kind: Secret metadata: name: secret-sa-sample annotations: kubernetes.io/service-account.name: 'sa-name'",                                                                                                                // gitleaks:allow
		"kubernetes.yml":  "apiVersion: v1 data: password: UyFCXCpkJHpEc2I9 username: YWRtaW4= kind: Secret metadata: creationTimestamp: '2022-06-28T17:44:13Z' name: db-user-pass namespace: default resourceVersion: '12708504' uid: 91becd59-78fa-4c85-823f-6d44436242ac type: Opaque", // gitleaks:allow
	}
	return validateWithPaths(r, tps, nil)
}

// KubernetesSecretWithDataAfter validates if we detected a kubernetes secret which contains data, after the resource identifier!
func KubernetesSecretWithDataAfter() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "kubernetes-secret-with-data-after",
		Description: "Possible Kubernetes Secret detected, posing a risk of leaking credentials/tokens from your deployments",
		// We try to match secrets by looking if we have the keyword
		Regex: generateUniqueTokenRegex(`(?i)(?:\bkind:\s*Secret\b)\W+(?:\w+\W+){0,200}?\b(data)\b.*`, true),

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
		"kubernetes.yaml": "apiVersion: v1 kind: Secret data: extra: YmFyCg== metadata: name: secret-sa-sample annotations: kubernetes.io/service-account.name: 'sa-name'",                                                                                                                // gitleaks:allow
		"kubernetes.yml":  "apiVersion: v1 kind: Secret data: password: UyFCXCpkJHpEc2I9 username: YWRtaW4= metadata: creationTimestamp: '2022-06-28T17:44:13Z' name: db-user-pass namespace: default resourceVersion: '12708504' uid: 91becd59-78fa-4c85-823f-6d44436242ac type: Opaque", // gitleaks:allow
	}

	return validateWithPaths(r, tps, nil)
}
