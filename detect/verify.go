package detect

import (
	b64 "encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"golang.org/x/exp/maps"

	"github.com/zricethezav/gitleaks/v8/report"
)

var base64HelperPat = regexp.MustCompile(`\${base64\("(.+?)"\)}`)
var urlEncodePat = regexp.MustCompile(`\${urlEncode\("(.+?)"\)}`)

// Verify will iterate through findings and verify them against validation
// fields defined in the rule
func (d *Detector) Verify(findings []report.Finding) []report.Finding {
	// Build lookups
	findingsByRuleID := map[string][]report.Finding{}
	secretsByRuleID := map[string]map[string]struct{}{}
	retFindings := []report.Finding{}
	verifiableFindings := []report.Finding{}
	findingBySecret := map[string]string{}

	for _, f := range findings {
		// Add finding to lookup
		findingsByRuleID[f.RuleID] = append(findingsByRuleID[f.RuleID], f)
		if _, ok := secretsByRuleID[f.RuleID]; !ok {
			secretsByRuleID[f.RuleID] = map[string]struct{}{}
		}
		secretsByRuleID[f.RuleID][f.Secret] = struct{}{}

		// Get the rule associated with the finding
		rule := d.Config.Rules[f.RuleID]

		// If rule.Verify is empty or the finding is skipped, continue
		if rule.Verify == nil || f.Status == report.Skipped {
			if rule.Report {
				// Exclude findings if rule.Report is false
				retFindings = append(retFindings, f)
			}
			continue
		}
		// Add to verifiable findings
		verifiableFindings = append(verifiableFindings, f)
	}

	// Iterate through the findings to verify
FindingLoop:
	for i, f := range verifiableFindings {
		logger := log.With().
			Str("rule-id", f.RuleID).
			Str("secret", f.Secret). // TODO: Properly redact this?
			Logger()

		rule := d.Config.Rules[f.RuleID]
		verify := rule.Verify

		// Prepare required IDs and placeholders
		requiredIDs := verify.GetRequiredIDs()
		rulePlaceholder := fmt.Sprintf("${%s}", f.RuleID)
		placeholderByRequiredID := make(map[string]string)
		for requiredID := range requiredIDs {
			placeholderByRequiredID[requiredID] = fmt.Sprintf("${%s}", requiredID)
		}

		// Collect findings per required ID
		findingsPerRequiredID := make(map[string][]string)
		for requiredID := range requiredIDs {
			secrets := maps.Keys(secretsByRuleID[requiredID])
			if len(secrets) == 0 {
				verifiableFindings[i].Status = report.Skipped
				verifiableFindings[i].StatusReason = fmt.Sprintf("No results for required rule: %s", requiredID)
				continue FindingLoop
			} else if len(secrets) > 3 {
				verifiableFindings[i].Status = report.Skipped
				verifiableFindings[i].StatusReason = fmt.Sprintf("Excessive number of results for required rule: %s", requiredID)
				continue FindingLoop
			}

			// Store the finding secret for later use as attributes
			findingsPerRequiredID[requiredID] = secrets
			for _, secret := range secrets {
				findingBySecret[secret] = requiredID
			}
		}

		// Expand URL placeholders
		urls, err := expandPlaceholdersInString(verify.URL, rulePlaceholder, f.Secret, placeholderByRequiredID, findingsPerRequiredID)
		if err != nil {
			verifiableFindings[i].Status = report.Error
			verifiableFindings[i].StatusReason = err.Error()
			continue
		}
		if len(urls) == 0 {
			// No placeholders to replace, use the original URL
			urls = []string{verify.URL}
		}

		// Expand header placeholders
		setsOfHeaders := map[string][]string{}
		for k, v := range verify.GetDynamicHeaders() {
			headers, err := expandPlaceholdersInString(v, rulePlaceholder, f.Secret, placeholderByRequiredID, findingsPerRequiredID)
			if err != nil {
				verifiableFindings[i].Status = report.Error
				verifiableFindings[i].StatusReason = err.Error()
				continue FindingLoop
			}
			setsOfHeaders[k] = headers
		}

		// Generate header combinations
		headerCombinations := generateHeaderCombinations(setsOfHeaders)

		// Iterate through URLs and header combinations
		for _, targetUrl := range urls {
			for _, headerCombination := range headerCombinations {
				// Add static headers to headerCombination
				for k, v := range verify.GetStaticHeaders() {
					headerCombination[k] = v
				}

				// Send verification request
				resp, exists := d.VerifyCache.Get(targetUrl, headerCombination)
				if !exists {
					logger.Debug().
						Str("method", verify.HTTPVerb).
						Str("url", targetUrl).
						Fields(map[string]interface{}{"headers": headerCombination}).
						Msg("Sending verification request...")

					req, err := http.NewRequest(verify.HTTPVerb, targetUrl, nil)

					// TODO make configurable (globally and per rule)
					// ctx, cancel := context.WithTimeout(context.Background(), timeout)
					// defer cancel()

					if err != nil {
						logger.Error().Err(err).Msg("Failed to construct verification request")
						verifiableFindings[i].Status = report.Error
						verifiableFindings[i].StatusReason = err.Error()
						continue
					}

					for key, val := range headerCombination {
						// TODO: Does order matter?
						// do encoding if needed so we can attribute supplemental findings
						if strings.Contains(val, "${base64") {
							val = base64HelperPat.ReplaceAllStringFunc(val, func(s string) string {
								submatch := base64HelperPat.FindStringSubmatch(s)
								return b64.StdEncoding.EncodeToString([]byte(submatch[1]))
							})
						}
						if strings.Contains(val, "${urlEncode") {
							val = urlEncodePat.ReplaceAllStringFunc(val, func(s string) string {
								submatch := urlEncodePat.FindStringSubmatch(s)
								return url.QueryEscape(submatch[1])
							})
						}
						req.Header.Add(key, val)
					}

					// TODO: Implement retry with backoff if needed
					resp, err = d.HTTPClient.Do(req)
					if err != nil {
						logger.Error().Err(err).Msg("Failed to send verification request")
						verifiableFindings[i].Status = report.Error
						verifiableFindings[i].StatusReason = err.Error()
						continue
					}

					// Set cache
					d.VerifyCache.Set(targetUrl, headerCombination, resp)
				}

				// TODO: Represent this in a better way? Conditional/lazy evaluation?
				var (
					isValidStatus, status = isValidStatus(resp.StatusCode, verify.ExpectedStatus)
					isValidBody, body     = isValidBody(resp, verify.ExpectedBodyContains)
				)
				if (len(verify.ExpectedStatus) == 0 || isValidStatus) && (len(verify.ExpectedBodyContains) == 0 || isValidBody) {
					verifiableFindings[i].Status = report.ConfirmedValid
					verifiableFindings[i].StatusReason = ""
					// Build attributes for multi-part rules
					// TODO: I don't think this works for base64-encoded secrets.
					if len(requiredIDs) > 0 {
						attributes := collectAttributes(targetUrl, headerCombination, findingBySecret)
						verifiableFindings[i].Attributes = attributes
					}
					if !exists {
						var sb strings.Builder
						if status != 0 {
							sb.WriteString(fmt.Sprintf("matched status condition '%d'", status))
						}
						if body != "" {
							if status != 0 {
								sb.WriteString(", ")
							}
							sb.WriteString(fmt.Sprintf("matched body condition '%s'", body))
						}
						logger.Debug().Msgf("Secret is valid: %s", sb.String())
					}
					goto RuleLoopEnd
				} else {
					if verifiableFindings[i].Status == report.ConfirmedValid {
						// If the finding was already confirmed valid, don't change the status.
						// TODO: this means that if there is a valid multi-part rule that has a reported secret
						// with _multiple_ valid attributes, only one of them will be reported as valid.
						// This is a limitation of the current implementation.
						goto RuleLoopEnd
					}
					verifiableFindings[i].Status = report.ConfirmedInvalid
					var sb strings.Builder
					if status != 0 {
						sb.WriteString(fmt.Sprintf("status code '%d'", status))
					}
					if body != "" {
						if status != 0 {
							sb.WriteString(", ")
						}
						sb.WriteString(fmt.Sprintf("body '%s'", body))
					}
					verifiableFindings[i].StatusReason = fmt.Sprintf("Status code '%d'", status)
					if !exists {
						logger.Debug().Msgf("Secret is not valid: received %s", sb.String())
					}
				}
			}
		}
	RuleLoopEnd:
	}

	if d.Verification {
		// Return only verified findings
		verifiedFindings := make([]report.Finding, 0)
		for _, f := range verifiableFindings {
			if f.Status == report.ConfirmedValid {
				verifiedFindings = append(verifiedFindings, f)
			}
		}
		return verifiedFindings
	}

	// Return all findings
	return append(retFindings, verifiableFindings...)
}

// expandPlaceholdersInString expands placeholders in a template string using the provided findings
func expandPlaceholdersInString(template, rulePlaceholder, secret string, placeholderByRequiredID map[string]string, secretsByRequiredID map[string][]string) ([]string, error) {
	// Replace the rule's own placeholder with its secret
	template = strings.ReplaceAll(template, rulePlaceholder, secret)

	// Collect placeholders and their possible values
	placeholders := []string{}
	secretsByPlaceholder := [][]string{}
	for requiredID, placeholder := range placeholderByRequiredID {
		placeholders = append(placeholders, placeholder)
		secrets := secretsByRequiredID[requiredID]
		// This should never happen.
		// Leaving it in, in case we silently break it while prototyping.
		if len(secrets) == 0 {
			return []string{}, fmt.Errorf("no secret(s) provided for placeholder: %s (THIS IS A BUG!)", placeholder)
		}
		secretsByPlaceholder = append(secretsByPlaceholder, secrets)
	}

	// If no placeholders, return the template as is
	if len(placeholders) == 0 {
		return []string{template}, nil
	}

	// Generate all combinations
	combinations := cartesianProduct(secretsByPlaceholder)

	// Replace placeholders with combinations
	var results []string
	for _, combo := range combinations {
		result := template
		for i, placeholder := range placeholders {
			result = strings.ReplaceAll(result, placeholder, combo[i])
		}
		results = append(results, result)
	}
	return results, nil
}

// collectAttributes collects attributes from the URL and headers based on findings
func collectAttributes(url string, headers map[string]string, findingBySecret map[string]string) map[string]string {
	attributes := make(map[string]string)
	// Check for secrets used in URL
	for secret, ruleID := range findingBySecret {
		if strings.Contains(url, secret) {
			attributes[ruleID] = secret
		}
	}
	// Check for secrets used in headers
	for _, v := range headers {
		for secret, ruleID := range findingBySecret {
			if strings.Contains(v, secret) {
				attributes[ruleID] = secret
			}
		}
	}
	return attributes
}

// Function to compute the Cartesian product of a slice of slices
func cartesianProduct(slices [][]string) [][]string {
	var result [][]string
	var helper func([]string, int)
	helper = func(current []string, index int) {
		if index == len(slices) {
			temp := make([]string, len(current))
			copy(temp, current)
			result = append(result, temp)
			return
		}
		for _, s := range slices[index] {
			helper(append(current, s), index+1)
		}
	}
	helper([]string{}, 0)
	return result
}

// This function generates all combinations of header values
func generateHeaderCombinations(setsOfHeaders map[string][]string) []map[string]string {
	if len(setsOfHeaders) == 0 {
		return []map[string]string{{}}
	}
	keys := maps.Keys(setsOfHeaders)
	combinations := []map[string]string{{}}

	for _, key := range keys {
		var temp []map[string]string
		for _, combo := range combinations {
			for _, value := range setsOfHeaders[key] {
				newCombo := maps.Clone(combo)
				newCombo[key] = value
				temp = append(temp, newCombo)
			}
		}
		combinations = temp
	}
	return combinations
}

// isValidStatus checks if the status code matches any of the expected status patterns.
func isValidStatus(status int, expectedStatuses []int) (bool, int) {
	for _, expectedStatus := range expectedStatuses {
		// Check if the expectedStatus is an exact match
		if status == expectedStatus {
			log.Debug().Int("status", status).Msgf("Status matches condition: %d", expectedStatus)
			return true, expectedStatus
		}
	}
	return false, status
}

func isValidBody(resp *http.Response, expectedBodyContains []string) (bool, string) {
	// TODO: Don't ignore error?
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	for _, b := range expectedBodyContains {
		if strings.Contains(bodyStr, b) {
			log.Debug().Str("body", bodyStr).Msgf("Body matches condition: %s", b)
			return true, b
		}
	}
	return false, bodyStr
}
