package rules

import (
	"fmt"
	"strings"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

// GCPServiceAccount returns a rule for detecting Google Cloud service account credentials.
// The PrivateKey rule is configured to allow these keys to prevent duplicate findings since
// Google Cloud Service Account keys contain a private key.
func GCPServiceAccount() *config.Rule {
	// Define rule metadata.
	r := config.Rule{
		Description: "Discovered a Google Cloud (GCP) service account key file, which comes bundled with a private key and service account information",
		RuleID:      "gcp-service-account-key",
		Regex:       regexp.MustCompile(`(?s)\{\s*(?:(?:.*?"type"\s*:\s*"service_account".*?"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----[\s\S-]{64,}?-----END PRIVATE KEY-----[\s\S]*?")|(?:.*?"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----[\s\S-]{64,}?-----END PRIVATE KEY-----[\s\S]*?".*?"type"\s*:\s*"service_account")).*?\}`),
		Entropy:     5,
		Keywords: []string{
			"service_account",
		},
		Tags: []string{
			"gcp",
			"google",
		},
	}

	projectId := secrets.NewSecret(`[a-z][-a-z0-9]{4,28}[a-z0-9]{1}`)
	privateKeyId := secrets.NewSecret(`[a-f0-9]{40}`)
	clientId := secrets.NewSecret(`[0-9]{21}`)
	privateKey := secrets.NewSecret(
		`-----BEGIN PRIVATE KEY-----\n` +
			`(?:[A-Za-z0-9+/=]{60}\n){10}` +
			`[A-Za-z0-9+/=]{40}=\n` +
			`-----END PRIVATE KEY-----\n`,
	)

	lowEntropyKey := strings.Repeat("X", 1500)

	tps := []string{
		// "type": "service_account" at beginning
		fmt.Sprintf(
			`{
				"type": "service_account",
				"project_id": "%s",
				"private_key_id": "%s",
				"private_key": "%s",
				"client_email": "gitleaks-test@%s.iam.gserviceaccount.com",
				"client_id": "%s",
				"auth_uri": "https://accounts.google.com/o/oauth2/auth",
				"token_uri": "https://oauth2.googleapis.com/token",
				"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
				"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/gitleaks-test%%40%s.iam.gserviceaccount.com",
				"universe_domain": "googleapis.com"
			}`, projectId, privateKeyId, privateKey, projectId, clientId, projectId),
		// "type": "service_account" at end
		fmt.Sprintf(
			`{
					"project_id": "%s",
					"private_key_id": "%s",
					"private_key": "%s",
					"client_email": "gitleaks-test@%s.iam.gserviceaccount.com",
					"client_id": "%s",
					"auth_uri": "https://accounts.google.com/o/oauth2/auth",
					"token_uri": "https://oauth2.googleapis.com/token",
					"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
					"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/gitleaks-test%%40%s.iam.gserviceaccount.com",
					"universe_domain": "googleapis.com",
					"type": "service_account",
				}`, projectId, privateKeyId, privateKey, projectId, clientId, projectId),
		fmt.Sprintf(
			`{
				"type": "service_account",
				"project_id": "%s",
				"private_key_id": "%s",
				"private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCy1yG25m+cplha\n8h1Jmd9m15gGabp2Uk5B/lgHglYiE+TRH7GvLTg30x9FIoarZR5SLKWaSQ50JPNL\npf5XlmiPmwRyY0hCQvDwPy0xX0iNCO/OGInGT0+oKXDtVb4e3NSp1sAmIVSVYyWg\nlwDl0W28t9rZdRprMTA0NU5GMeTGolsFxjhTp313Ss7iZ6fsg6TDz5Gv1Js0iXyl\nKDj1nIFaokZ7ERTOMGTQ4TTKgHIHhp4fVBsjJp4cKvv48DhabHLyz4zQhfzEK0dj\n2KT2Kkp1GS1JwKRApxHVBPgm55CVsAMLTxHBVgvujcDKavfLLANSWpOZnIiNdbsE\n1BWF/2VtAgMBAAECggEAGvSeGklFTWEtNBgGHg/ZQlEAkwbgmfDx5rSFZCxa+yvw\ncyzJxVOVg6SItAzuK2tEVLJyC30zdoITQbW1TlJXVD3TP8KDI6mfUzbSgvyPnOJZ\n8sB0E7Xklb4ZTUx9KX2zeB3sPFMNwq58/2WDNyCH38f+boReBQYW8+eM8ruWdfHF\nvqm7M+JxiAH1pD/QOqkEo5SdkIUd2Cg6CbvQtLAUx7Daom09zR79OkezZ2+SWFff\n3nG4xnSUPF22UzZQw1gsyduT9p24ibncltlGVvtu/Mv7FAQdAo0gTDozVKGIdNjH\nCFjsEpduwnRFwFxbieKHbTbCBCn9A7PJNIphCyDhaQKBgQDwyw7kwCUbKGIMkcdL\nEKBcIeSJgVVP0kKb9Y4Z9pHqoFfutLzCrOrAYimhRAt86FEbojJJoMEL0o0lSnME\nRSxq5nFXwQSHFMKdOyA+ojlXUiB3f4CEUAxJ44Q6CbbZth7DJyt2cWGSNLB/xAEg\nJyKQb0aDRf/Zfqmsvdj+HLAigwKBgQC+InjfOPek2WsgYqBZr1Td16K/e7W1gOhv\nH033zEbveHkJD11IKzQP5l+6hokFteFG0k2jEB+HK8MxGufgBQ3asbQmYxFRAJFl\nkQKyTrZGvHlPNsGt1vGuj/EF4Vp2ih2dXhoPA8Y0vXc+GyTAnvShSJz5FPJVCHPq\n0MMSSvAVTwKBgCjcPEXC+Uj3fFPntOrfAmc/9RkEUma+JkFy1M9BERfAZ8uA7fsW\n/qrwvWG5Oz3R6lmHF4N4/Ok1rG/kh0n1NwlY22jpvwvxEOk/bERUoOhZblr4zuUk\n9EDhk8GJfnbJOcUh83Ug3k7CFCVKLGq5WVsrFssV6MmOfdprSNQuKBFjAoGBAKWu\n+m9igAJp570X1K1yaNzMLKj5z3UzuNgkile17dZ9v9MSTXI3G64DTUYIOFz+iimh\n1z+SLDco/nXLAWYoYVNCaT7OM2fHu+uqupPQnWv0jy1lBM9Mr9wy2JAMOT10y6u3\nNbQB0PViaQd4tcUYfwoQcaFoDGfm7sQfWO2W2bFnAoGAD5NRuS5/EEqm8dZY6EKw\nbX+7HNBeYDf7A5Uh15TYIu5ckM30sr0rg2/RzrW6qdfD93EwKxc3mAi+zxbA/EnU\nDVQ3n0BNNR2kEzOSXm2uRGRt6EjFlke1YUqVytWlNBi99expsFRxihD996MBfYWJ\nxElNa3RTdwMPGE02C0y7fBg=\n-----END PRIVATE KEY-----\n",
				"client_email": "gitleaks-test@%s.iam.gserviceaccount.com",
				"client_id": "%s",
				"auth_uri": "https://accounts.google.com/o/oauth2/auth",
				"token_uri": "https://oauth2.googleapis.com/token",
				"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
				"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/gitleaks-test%%40%s.iam.gserviceaccount.com",
				"universe_domain": "googleapis.com"
			}`, projectId, privateKeyId, projectId, clientId, projectId),
	}

	fps := []string{
		// No `"private_key"`
		fmt.Sprintf(
			`{
				"type": "service_account",
				"project_id": "%s",
				"private_key_id": "%s",
				"client_email": "gitleaks-test@%s.iam.gserviceaccount.com",
				"client_id": "%s",
				"auth_uri": "https://accounts.google.com/o/oauth2/auth",
				"token_uri": "https://oauth2.googleapis.com/token",
				"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
				"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/gitleaks-test%%40%s.iam.gserviceaccount.com",
				"universe_domain": "googleapis.com"
			}`, projectId, privateKeyId, projectId, clientId, projectId),
		// No `"type": "service_account"`
		fmt.Sprintf(
			`{
				"project_id": "%s",
				"private_key_id": "%s",
				"private_key": "%s",
				"client_email": "gitleaks-test@%s.iam.gserviceaccount.com",
				"client_id": "%s",
				"auth_uri": "https://accounts.google.com/o/oauth2/auth",
				"token_uri": "https://oauth2.googleapis.com/token",
				"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
				"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/gitleaks-test%%40%s.iam.gserviceaccount.com",
				"universe_domain": "googleapis.com"
			}`, projectId, privateKeyId, privateKey, projectId, clientId, projectId),
		// Low entropy `"private_key"`
		fmt.Sprintf(
			`{
				"type": "service_account",
				"project_id": "%s",
				"private_key_id": "%s",
				"private_key": "-----BEGIN PRIVATE KEY-----%s-----END PRIVATE KEY-----\n",
				"client_email": "gitleaks-test@%s.iam.gserviceaccount.com",
				"client_id": "%s",
				"auth_uri": "https://accounts.google.com/o/oauth2/auth",
				"token_uri": "https://oauth2.googleapis.com/token",
				"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
				"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/gitleaks-test%%40%s.iam.gserviceaccount.com",
				"universe_domain": "googleapis.com"
    	}`, projectId, privateKeyId, lowEntropyKey, projectId, clientId, projectId),
	}
	return utils.Validate(r, tps, fps)
}

func GCPAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "gcp-api-key",
		Description: "Uncovered a GCP API key, which could lead to unauthorized access to Google Cloud services and data breaches.",
		Regex:       utils.GenerateUniqueTokenRegex(`AIza[\w-]{35}`, false),
		Entropy:     4,
		Keywords:    []string{"AIza"},
		Allowlists: []*config.Allowlist{
			{
				Regexes: []*regexp.Regexp{
					// example keys from https://github.com/firebase/firebase-android-sdk
					regexp.MustCompile(`AIzaSyabcdefghijklmnopqrstuvwxyz1234567`),
					regexp.MustCompile(`AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs`),
					regexp.MustCompile(`AIzaSyCkEhVjf3pduRDt6d1yKOMitrUEke8agEM`),
					regexp.MustCompile(`AIzaSyDMAScliyLx7F0NPDEJi1QmyCgHIAODrlU`),
					regexp.MustCompile(`AIzaSyD3asb-2pEZVqMkmL6M9N6nHZRR_znhrh0`),
					regexp.MustCompile(`AIzayDNSXIbFmlXbIE6mCzDLQAqITYefhixbX4A`),
					regexp.MustCompile(`AIzaSyAdOS2zB6NCsk1pCdZ4-P6GBdi_UUPwX7c`),
					regexp.MustCompile(`AIzaSyASWm6HmTMdYWpgMnjRBjxcQ9CKctWmLd4`),
					regexp.MustCompile(`AIzaSyANUvH9H9BsUccjsu2pCmEkOPjjaXeDQgY`),
					regexp.MustCompile(`AIzaSyA5_iVawFQ8ABuTZNUdcwERLJv_a_p4wtM`),
					regexp.MustCompile(`AIzaSyA4UrcGxgwQFTfaI3no3t7Lt1sjmdnP5sQ`),
					regexp.MustCompile(`AIzaSyDSb51JiIcB6OJpwwMicseKRhhrOq1cS7g`),
					regexp.MustCompile(`AIzaSyBF2RrAIm4a0mO64EShQfqfd2AFnzAvvuU`),
					regexp.MustCompile(`AIzaSyBcE-OOIbhjyR83gm4r2MFCu4MJmprNXsw`),
					regexp.MustCompile(`AIzaSyB8qGxt4ec15vitgn44duC5ucxaOi4FmqE`),
					regexp.MustCompile(`AIzaSyA8vmApnrHNFE0bApF4hoZ11srVL_n0nvY`),
				},
			},
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("gcp", secrets.NewSecret(`AIza[\w-]{35}`))
	tps = append(tps,
		// non-word character at end
		`AIzaSyNHxIf32IQ1a1yjl3ZJIqKZqzLAK1XhDk-`, // gitleaks:allow
	)
	fps := []string{
		`GWw4hjABFzZCGiRpmlDyDdo87Jn9BN9THUA47muVRNunLxsa82tMAdvmrhOqNkRKiYMEAFbTJAIzaTesb6Tscfcni8vIpWZqNCXFDFslJtVSvFDq`, // text boundary start
		`AIzaTesb6Tscfcni8vIpWZqNCXFDFslJtVSvFDqabcd123`,                                                                   // text boundary end
		`apiKey: "AIzaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`,                                                                // not enough entropy
		`AIZASYCO2CXRMC9ELSKLHLHRMBSWDEVEDZTLO2O`,                                                                          // incorrect case
		// example keys from https://github.com/firebase/firebase-android-sdk
		`AIzaSyabcdefghijklmnopqrstuvwxyz1234567`,
		`AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs`,
		`AIzaSyCkEhVjf3pduRDt6d1yKOMitrUEke8agEM`,
		`AIzaSyDMAScliyLx7F0NPDEJi1QmyCgHIAODrlU`,
		`AIzaSyD3asb-2pEZVqMkmL6M9N6nHZRR_znhrh0`,
		`AIzayDNSXIbFmlXbIE6mCzDLQAqITYefhixbX4A`,
		`AIzaSyAdOS2zB6NCsk1pCdZ4-P6GBdi_UUPwX7c`,
		`AIzaSyASWm6HmTMdYWpgMnjRBjxcQ9CKctWmLd4`,
		`AIzaSyANUvH9H9BsUccjsu2pCmEkOPjjaXeDQgY`,
		`AIzaSyA5_iVawFQ8ABuTZNUdcwERLJv_a_p4wtM`,
		`AIzaSyA4UrcGxgwQFTfaI3no3t7Lt1sjmdnP5sQ`,
		`AIzaSyDSb51JiIcB6OJpwwMicseKRhhrOq1cS7g`,
		`AIzaSyBF2RrAIm4a0mO64EShQfqfd2AFnzAvvuU`,
		`AIzaSyBcE-OOIbhjyR83gm4r2MFCu4MJmprNXsw`,
		`AIzaSyB8qGxt4ec15vitgn44duC5ucxaOi4FmqE`,
		`AIzaSyA8vmApnrHNFE0bApF4hoZ11srVL_n0nvY`,
	}
	return utils.Validate(r, tps, fps)
}
