package detect

import (
	b64 "encoding/base64"
	"fmt"
	"golang.org/x/exp/maps"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/report"
)

// Verify will iterate through findings and Verify them against validation
// fields defined in the rule
func (d *Detector) Verify(findings []report.Finding) []report.Finding {
	client := &http.Client{}
	// build lookups.
	findingsByRuleID := map[string][]report.Finding{}
	secretsByRuleID := map[string]map[string]struct{}{}
	retFindings := []report.Finding{}
	verifiableFindings := []*report.Finding{}
	findingBySecret := map[string]string{}
	for _, f := range findings {
		// add finding to lookup
		findingsByRuleID[f.RuleID] = append(findingsByRuleID[f.RuleID], f)
		if _, ok := secretsByRuleID[f.RuleID]; !ok {
			secretsByRuleID[f.RuleID] = map[string]struct{}{}
		}
		secretsByRuleID[f.RuleID][f.Secret] = struct{}{}

		// this should always return a valid rule
		rule := d.Config.Rules[f.RuleID]
		// if rule.Verify is empty or the finding is skipped, continue
		if rule.Verify.URL == "" || f.Status == report.Skipped {
			if rule.Report {
				// Exclude findings if |rule.report| is false.
				retFindings = append(retFindings, f)
			}
			continue
		}
		verifiableFindings = append(verifiableFindings, &f)
	}

	// iterate through the findings to Verify
	for i, f := range verifiableFindings {
		logger := log.With().
			Str("rule-id", f.RuleID).
			Str("secret", f.Secret). // TODO: Properly redact this?
			Logger()
		var (
			rule = d.Config.Rules[f.RuleID]
			err  error
		)

		// Expand URL placeholders, if needed.
		var urls []string
		url := rule.Verify.URL
		if rule.Verify.GetPlaceholderInUrl() {
			urls, err = expandUrlPlaceholders(url, rule.Verify.GetRequiredIDs(), f, secretsByRuleID, findingBySecret)
			if err != nil {
				f.Status = report.Skipped
				f.StatusReason = err.Error()
				continue
			}
		} else {
			// There is no substitution, just use the original url.
			urls = append(urls, url)
		}

		// Expand header placeholders, if needed.
		var setsOfHeaders map[string][]string
		if len(rule.Verify.GetDynamicHeaders()) > 0 {
			setsOfHeaders, err = expandHeaderPlaceholders(rule.Verify.GetDynamicHeaders(), rule.Verify.GetRequiredIDs(), f, secretsByRuleID, findingBySecret)
			if err != nil {
				f.Status = report.Skipped
				f.StatusReason = err.Error()
				continue
			}
		}

		// iterate through urls and header combinations
		// make request
		for _, url := range urls {
			headerCombinations := generateHeaderCombinations(setsOfHeaders)
			for _, headerCombination := range headerCombinations {
				// add static headers to headerCombination
				for k, v := range rule.Verify.GetStaticHeaders() {
					headerCombination[k] = v
				}

				resp, exists := d.VerifyCache.Get(url, headerCombination)
				if !exists {
					logger.Debug().
						Str("method", rule.Verify.HTTPVerb).
						Str("url", url).
						Fields(map[string]interface{}{"headers": headerCombination}).
						Msgf("Sending verification request...")
					req, err := http.NewRequest(rule.Verify.HTTPVerb, url, nil)
					if err != nil {
						logger.Error().Err(err).Msgf("Failed to construct verification request")
						verifiableFindings[i].Status = report.Error
						verifiableFindings[i].StatusReason = err.Error()
						continue
					}
					for key, val := range headerCombination {
						// TODO: Does order matter?
						// do encoding if needed so we can attribute supplemental findings
						if strings.Contains(val, "${base64") {
							val = HelperFunctions.Base64Encode(val)
						}
						if strings.Contains(val, "${urlEncode") {
							val = HelperFunctions.UrlEncode(val)
						}
						req.Header.Add(key, val)
					}

					// TODO implement a retry if set with a polite backoff
					resp, err = client.Do(req)
					if err != nil {
						logger.Error().Err(err).Msgf("Failed send verification request")
						verifiableFindings[i].Status = report.Error
						verifiableFindings[i].StatusReason = err.Error()
						continue
					}

					// set cache
					d.VerifyCache.Set(url, headerCombination, resp)
				}

				if isValidStatus(resp.StatusCode, rule.Verify.ExpectedStatus) {
					verifiableFindings[i].Status = report.ConfirmedValid
					// Build attributes for multi-part rules.
					if len(rule.Verify.GetRequiredIDs()) > 0 {
						attributes := make(map[string]string)
						// Check for additional secrets used in URL.
						if rule.Verify.GetPlaceholderInUrl() {
							for secret, ruleID := range findingBySecret {
								if strings.Contains(url, secret) {
									attributes[ruleID] = secret
								}
							}
						}
						// Check for additional secrets used in headers.
						for _, v := range headerCombination {
							for secret, ruleID := range findingBySecret {
								if strings.Contains(v, secret) {
									attributes[ruleID] = secret
								}
							}
						}
						verifiableFindings[i].Attributes = attributes
					}
					if !exists {
						logger.Debug().Msgf("Secret is valid: received status code '%d'", resp.StatusCode)
					}

					goto RuleLoopEnd
				} else {
					verifiableFindings[i].Status = report.ConfirmedInvalid
					verifiableFindings[i].StatusReason = fmt.Sprintf("Status code '%d'", resp.StatusCode)
					if !exists {
						logger.Debug().Msgf("Secret is not valid: received status code '%d'", resp.StatusCode)
					}
				}
			}
		}
	RuleLoopEnd:
	}

	if d.Verification {
		// Return only verified findings.
		verifiedFindings := make([]report.Finding, 0)
		for _, f := range verifiableFindings {
			if f.Status == report.ConfirmedValid {
				verifiedFindings = append(verifiedFindings, *f)
			}
		}
		return verifiedFindings
	}

	// Return all findings.
	for _, f := range verifiableFindings {
		retFindings = append(retFindings, *f)
	}
	return retFindings
}

// TODO: can some of the duplicated logic in expandHeaderPlaceholders be reduced?
// TODO: decide on the arbitrary max limit of 3 results?
func expandUrlPlaceholders(url string, requiredIDs map[string]struct{}, finding *report.Finding, secretsByRuleID map[string]map[string]struct{}, findingsBySecret map[string]string) ([]string, error) {
	// e.g., a matrix of [[clientid1, clientid2], [secret]]
	var (
		urls                    []string
		rulePlaceholder         = fmt.Sprintf("${%s}", finding.RuleID)
		placeholderByRequiredID = make(map[string]string)
		placeholders            = []string{}
		findingsPerPlaceholder  = [][]string{}
	)
	for requiredID := range requiredIDs {
		placeholderByRequiredID[requiredID] = fmt.Sprintf("${%s}", requiredID)
	}

	// Interpolate the finding secret.
	if strings.Contains(url, rulePlaceholder) {
		url = strings.Replace(url, rulePlaceholder, finding.Secret, -1)
	}

	// Collect the placeholders and their possible findings
	for requireID, placeholder := range placeholderByRequiredID {
		placeholders = append(placeholders, placeholder)
		secrets := secretsByRuleID[requireID]
		if len(secrets) == 0 {
			return nil, fmt.Errorf("no results for required rule: %s", requireID)
		} else if len(secrets) > 3 {
			return nil, fmt.Errorf("excessive number of results for required rule: %s", requireID)
		}

		findingsPerPlaceholder = append(findingsPerPlaceholder, maps.Keys(secrets))
		for secret := range secrets {
			// Store the finding secret for later use as attributes
			findingsBySecret[secret] = requireID
		}
	}

	// Generate all combinations
	combinations := cartesianProduct(findingsPerPlaceholder)
	for _, combo := range combinations {
		u := url
		for i, placeholder := range placeholders {
			u = strings.Replace(u, placeholder, combo[i], -1)
		}
		urls = append(urls, u)
	}
	return urls, nil
}

func expandHeaderPlaceholders(headers map[string]string, requiredIDs map[string]struct{}, finding *report.Finding, secretsByRuleID map[string]map[string]struct{}, findingsBySecret map[string]string) (map[string][]string, error) {
	var (
		setsOfHeaders           = make(map[string][]string)
		rulePlaceholder         = fmt.Sprintf("${%s}", finding.RuleID)
		placeholderByRequiredID = make(map[string]string)
	)
	for requiredID := range requiredIDs {
		placeholderByRequiredID[requiredID] = fmt.Sprintf("${%s}", requiredID)
	}

	// Iterate through each dynamic header.
	for k, v := range headers {
		var (
			placeholders           []string
			findingsPerPlaceholder [][]string
		)

		// Interpolate the finding secret.
		if strings.Contains(v, rulePlaceholder) {
			v = strings.Replace(v, rulePlaceholder, finding.Secret, -1)
		}

		// Collect the placeholders and their possible findings
		for requireID, placeholder := range placeholderByRequiredID {
			placeholders = append(placeholders, placeholder)
			secrets := secretsByRuleID[requireID]
			if len(secrets) == 0 {
				return nil, fmt.Errorf("no results for required rule: %s", requireID)
			} else if len(secrets) > 3 {
				return nil, fmt.Errorf("excessive number of results for required rule: %s", requireID)
			}

			findingsPerPlaceholder = append(findingsPerPlaceholder, maps.Keys(secrets))
			for secret := range secrets {
				// Store the finding secret for later use as attributes
				findingsBySecret[secret] = requireID
			}
		}

		// Generate all combinations
		combinations := cartesianProduct(findingsPerPlaceholder)
		for _, combo := range combinations {
			headerValue := v
			for i, placeholder := range placeholders {
				headerValue = strings.Replace(headerValue, placeholder, combo[i], -1)
			}
			setsOfHeaders[k] = append(setsOfHeaders[k], headerValue)
		}
	}

	return setsOfHeaders, nil
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
	var keys []string
	for k := range setsOfHeaders {
		keys = append(keys, k)
	}

	// Start with a single empty combination
	var combinations []map[string]string
	combinations = append(combinations, make(map[string]string))

	for _, key := range keys {
		newCombinations := []map[string]string{}
		for _, oldValueMap := range combinations {
			for _, value := range setsOfHeaders[key] {
				// Copy the old combination and add a new value for the current key
				newValueMap := make(map[string]string)
				for k, v := range oldValueMap {
					newValueMap[k] = v
				}
				newValueMap[key] = value
				newCombinations = append(newCombinations, newValueMap)
			}
		}
		combinations = newCombinations
	}
	return combinations
}

// isValidStatus checks if the status code matches any of the expected status patterns.
func isValidStatus(status int, expectedStatuses []string) bool {
	statusStr := strconv.Itoa(status)

	for _, expectedStatus := range expectedStatuses {
		// Check if the expectedStatus is an exact match
		if expectedStatus == statusStr {
			return true
		}

		// Check if the expectedStatus is a range match (e.g., "2xx")
		if len(expectedStatus) == 3 && strings.HasSuffix(expectedStatus, "xx") {
			expectedPrefix := expectedStatus[0]
			statusPrefix := statusStr[0]
			if expectedPrefix == statusPrefix {
				return true
			}
		}
	}
	return false
}

func isValidBody(body string, bodyContains []string) bool {
	for _, b := range bodyContains {
		if strings.Contains(b, body) {
			return true
		}
	}
	return false
}

var base64HelperPat = regexp.MustCompile(`\${base64\("(.+?)"\)}`)
var urlEncodePat = regexp.MustCompile(`\${urlEncode\("(.+?)"\)}`)

var HelperFunctions = struct {
	Base64Encode func(s string) string
	UrlEncode    func(s string) string
}{
	// TODO: write these more efficiently
	Base64Encode: func(s string) string {
		return base64HelperPat.ReplaceAllStringFunc(s, func(s string) string {
			// Extract the capture group (without base64(...) wrapping)
			submatch := base64HelperPat.FindStringSubmatch(s)
			return b64.StdEncoding.EncodeToString([]byte(submatch[1]))
		})
	},
	// TODO: Is this necessary? If a query parameter is specified, is Go smart enough to encode it automatically?
	UrlEncode: func(s string) string {
		return urlEncodePat.ReplaceAllStringFunc(s, func(s string) string {
			submatch := urlEncodePat.FindStringSubmatch(s)
			return url.QueryEscape(submatch[1])
		})
	},
}
