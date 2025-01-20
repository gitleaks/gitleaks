package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

// OpenShift 4 user tokens are prefixed with `sha256~`.
// https://docs.redhat.com/en/documentation/openshift_container_platform/4.10/html-single/authentication_and_authorization/index#oauth-view-details-tokens_managing-oauth-access-tokens
func OpenshiftUserToken() *config.Rule {
	r := config.Rule{
		RuleID:      "openshift-user-token",
		Description: "Found an OpenShift user token, potentially compromising an OpenShift/Kubernetes cluster.",
		// TODO: Do tokens vary in length or are they always 43?
		Regex:   regexp.MustCompile(`\b(sha256~[\w-]{43})(?:[^\w-]|\z)`),
		Entropy: 3.5,
		Keywords: []string{
			"sha256~",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("oc", secrets.NewSecret("sha256~[\\w-]{43}"))
	tps = append(tps,
		`Authorization: Bearer sha256~kV46hPnEYhCWFnB85r5NrprAxggzgb6GOeLbgcKNsH0`, // https://github.com/openshift/console/blob/edae2305e01c2e0e8c33727af720ef960088eee3/dynamic-demo-plugin/README.md?plain=1#L114
		`oc login --token=sha256~ZBMKw9VAayhdnyANaHvjJeXDiGwA7Fsr5gtLKj3-eh- `,     // https://github.com/IBM/tekton-tutorial-openshift/blob/2a97d22ba282accad50821bca069210ea89de706/docs/lab1/0_setup.md?plain=1#L85
		"sha256~"+secrets.NewSecret(`[\w-]{43}`),
	)
	fps := []string{
		`--set kraken.kubeconfig.token.token="sha256~XXXXXXXXXX_PUT_YOUR_TOKEN_HERE_XXXXXXXXXXXX" \`, // https://github.com/krkn-chaos/krkn/blob/f3933f0e6239824eb9b5c46ff0e5d503b8465d6a/docs/index.md?plain=1#L307
		`oc login --token=sha256~_xxxxxx_xxxxxxxxxxxxxxxxxxxxxx-xxxxxxxxxx-X \
    --server=https://api.${zone}.appuio.cloud:6443`,
	}
	return utils.Validate(r, tps, fps)
}
