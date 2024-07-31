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
			"kind: Secret",
		},
		// Kubernetes secrets are always yaml files, we limit to common yaml-endings to make this rule more safe!
		Path: regexp.MustCompile(`\.(yaml|yml)$`),
	}

	// validate
	tps := []string{
		// Sample Kubernetes Secret from https://kubernetes.io/docs/concepts/configuration/secret/
		"apiVersion: v1 kind: Secret metadata: name: secret-sa-sample annotations: kubernetes.io/service-account.name: 'sa-name' type: kubernetes.io/service-account-token data: extra: YmFyCg==", // gitleaks:allow
	}
	return validate(r, tps, nil)
}
