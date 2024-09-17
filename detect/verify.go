package detect

import (
	b64 "encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/report"
)

var base64HelperPat = regexp.MustCompile(`\${base64\("(.+?)"\)}`)
var validatorReplaceRegex = regexp.MustCompile(`(?i)\${([a-z0-9\-]*)}`)

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

// Verify will iterate through findings and Verify them against validation
// fields defined in the rule
func (d *Detector) Verify(findings []report.Finding) []report.Finding {
	client := &http.Client{}
	// build lookups.
	findingsByRuleID := map[string][]report.Finding{}
	verifiableFindings := []report.Finding{}
	retFindings := []report.Finding{}
	findingBySecret := map[string]string{}
	for _, f := range findings {
		// add finding to lookup
		findingsByRuleID[f.RuleID] = append(findingsByRuleID[f.RuleID], f)

		// this should always return a valid rule
		rule := d.Config.Rules[f.RuleID]

		// if rule.Verify is empty, continue
		if rule.Verify.URL == "" || f.Status == report.Skipped {
			retFindings = append(retFindings, f)
			continue
		}

		verifiableFindings = append(verifiableFindings, f)
	}

	// iterate through the findings to Verify
	for i, f := range verifiableFindings {
		log.Debug().
			Str("rule-id", f.RuleID).
			Str("secret", f.Secret).
			Msg("Verifying finding")

		rule := d.Config.Rules[f.RuleID]
		setsOfHeaders := make(map[string][]string)
		staticHeaders := make(map[string]string)

		urls := []string{}

		// url replacement if needed
		// TODO support more than one replacement per url
		url := rule.Verify.URL
		urlMatches := validatorReplaceRegex.FindAllStringSubmatch(url, -1)
		for _, match := range urlMatches {
			ruleIDToReplace := match[1]
			potentialFindingsUsedForURLs := findingsByRuleID[ruleIDToReplace]
			for _, pf := range potentialFindingsUsedForURLs {
				urls = append(urls, strings.Replace(url, match[0], pf.Secret, -1))
			}
		}

		// if urls is empty, just use the original url. This means there is no substitution.
		if len(urls) == 0 {
			urls = append(urls, url)
		}

		for k, v := range rule.Verify.Headers {
			headerMatches := validatorReplaceRegex.FindAllStringSubmatch(v, -1)
			if len(headerMatches) == 0 {
				staticHeaders[k] = v
				continue
			}

			placeholders := []string{}
			findingsPerPlaceholder := [][]string{}

			// Collect the placeholders and their possible findings
			for _, match := range headerMatches {
				placeholder := match[0]
				ruleIDToReplace := match[1]
				potentialFindings := findingsByRuleID[ruleIDToReplace]

				secrets := []string{}
				for _, pf := range potentialFindings {
					secrets = append(secrets, pf.Secret)

					// Store the finding secret for later use as attributes
					findingBySecret[pf.Secret] = pf.RuleID
				}
				placeholders = append(placeholders, placeholder)
				findingsPerPlaceholder = append(findingsPerPlaceholder, secrets)
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

		// iterate through urls and header combinations
		// make request
		for _, url := range urls {
			headerCombinations := generateHeaderCombinations(setsOfHeaders)
			for _, headerCombination := range headerCombinations {
				// add static headers to headerCombination
				for k, v := range staticHeaders {
					headerCombination[k] = v
				}

				// check if finding secret is in headerCombination
				// if not, continue
				secretInHeaderCombinationOrURL := false
				for _, v := range headerCombination {
					if strings.Contains(v, f.Secret) {
						secretInHeaderCombinationOrURL = true
						break
					}
				}

				if strings.Contains(url, f.Secret) {
					secretInHeaderCombinationOrURL = true
				}

				// this is to prevent double counting of findings due to substitutions
				if !secretInHeaderCombinationOrURL {
					// TODO: re-enable this.
					// TODO: Check if it's in body as well.
					// TODO: Handle things like base64-encoding
					//continue
				}

				resp, exists := d.VerifyCache.Get(url, headerCombination)
				if !exists {
					req, err := http.NewRequest(rule.Verify.HTTPVerb, url, nil)
					if err != nil {
						log.Error().
							Str("rule", f.RuleID).
							Str("secret", f.Secret). // TODO: properly redact this?
							Err(err).
							Msgf("Failed to construct verification request")
						verifiableFindings[i].Status = report.Error
						verifiableFindings[i].StatusReason = err.Error()
						continue
					}
					for key, val := range headerCombination {
						// do base64 encoding if needed so we can attribute supplemental findings
						if strings.Contains(val, "${base64") {
							val = encodeBase64(val)
						}
						req.Header.Add(key, val)
					}

					// TODO implement a retry if set with a polite backoff
					resp, err = client.Do(req)
					if err != nil {
						log.Error().
							Str("rule", f.RuleID).
							Str("secret", f.Secret). // TODO: properly redact this?
							Err(err).
							Msgf("Failed send verification request")
						verifiableFindings[i].Status = report.Error
						verifiableFindings[i].StatusReason = err.Error()
						continue
					}

					// set cache
					d.VerifyCache.Set(url, headerCombination, resp)
				}

				if isValidStatus(resp.StatusCode, rule.Verify.ExpectedStatus) {
					verifiableFindings[i].Status = report.ConfirmedValid
					attributes := make(map[string]string)
					for _, v := range headerCombination {
						for secret, ruleID := range findingBySecret {
							if strings.Contains(v, secret) && secret != f.Secret {
								attributes[ruleID] = secret
							}
						}
					}
					verifiableFindings[i].Attributes = attributes
					goto RuleLoopEnd
				} else {
					verifiableFindings[i].Status = report.ConfirmedInvalid
					verifiableFindings[i].StatusReason = fmt.Sprintf("Status code '%d'", resp.StatusCode)
					if !exists {
						log.Debug().
							Str("rule", f.RuleID).
							Str("secret", f.Secret). // TODO: properly redact this?
							Msgf("Secret is not valid: received status code '%d'", resp.StatusCode)
					}
				}
			}
		}
	RuleLoopEnd:
	}

	if d.Verification {
		verifiedFindings := make([]report.Finding, 0)
		for _, f := range verifiableFindings {
			if f.Status == report.ConfirmedValid {
				verifiedFindings = append(verifiedFindings, f)
			}
		}
		return verifiedFindings
	}

	return append(retFindings, verifiableFindings...)
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

func encodeBase64(input string) string {
	// TODO: write this more efficiently
	return base64HelperPat.ReplaceAllStringFunc(input, func(s string) string {
		// Extract the capture group (without base64(...) wrapping)
		submatch := base64HelperPat.FindStringSubmatch(s)
		return b64.StdEncoding.EncodeToString([]byte(submatch[1]))
	})
}
