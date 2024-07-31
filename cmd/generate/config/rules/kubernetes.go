package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func KubernetesSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "kubernetes-secret",
		Description: "Possible Kubernetes Secret detected, posing a risk of leaking credentials/tokens from your deployments",
		// We only match based on the "kind:secret" value of all kubernetes secrets
		Regex: generateUniqueTokenRegex(`kind:\s*Secret`, true),

		Keywords: []string{
			"Secret",
		},
		// Kubernetes secrets are always yaml files, we limit to common yaml-endings to make this rule more safe!
		Path: regexp.MustCompile(`(?i)\.ya?ml$`),
	}

	// validate
	tps := map[string]string{
		// Sample Kubernetes Secret from https://kubernetes.io/docs/concepts/configuration/secret/
		"kubernetes.yaml": "apiVersion: v1 kind: Secret metadata: name: secret-sa-sample annotations: kubernetes.io/service-account.name: 'sa-name' type: kubernetes.io/service-account-token data: extra: YmFyCg==",                                                                      // gitleaks:allow
		"kubernetes.yml":  "apiVersion: v1 data: password: UyFCXCpkJHpEc2I9 username: YWRtaW4= kind: Secret metadata: creationTimestamp: '2022-06-28T17:44:13Z' name: db-user-pass namespace: default resourceVersion: '12708504' uid: 91becd59-78fa-4c85-823f-6d44436242ac type: Opaque", // gitleaks:allow
	}
	return validateWithPaths(r, tps, nil)
}
