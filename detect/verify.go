package detect

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/zricethezav/gitleaks/v8/report"
)

// Verify will iterate through findings and Verify them against validation
// fields defined in the rule
func (d *Detector) Verify(findings []report.Finding) []report.Finding {
	if !d.EnableExperimentalVerification {
		return findings
	}

	client := &http.Client{}
	validatorReplaceRegex := regexp.MustCompile(`(?i)\${([a-z0-9\-]{0,})}`)
	onlyVerifiedFindings := []report.Finding{}

	// build lookup of findings by ruleID
	findingsByRuleID := map[string][]report.Finding{}
	findingsToVerify := []report.Finding{}

	for _, f := range findings {
		// add finding to lookup
		findingsByRuleID[f.RuleID] = append(findingsByRuleID[f.RuleID], f)

		// this should always return a valid rule
		rule := d.Config.Rules[f.RuleID]

		// if rule.Verify is empty, continue
		if rule.Verify.URL == "" {
			continue
		}

		findingsToVerify = append(findingsToVerify, f)
	}

	// iterate through the findings to Verify
	for _, f := range findingsToVerify {
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
			}

			for _, match := range headerMatches {
				ruleIDToReplace := match[1]
				potentialFindingsUsedForHeaders := findingsByRuleID[ruleIDToReplace]
				for _, pf := range potentialFindingsUsedForHeaders {
					setsOfHeaders[k] = append(setsOfHeaders[k], strings.Replace(v, match[0], pf.Secret, -1))
				}
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
					continue
				}

				resp, exists := d.VerifyCache.Get(url, headerCombination)
				if !exists {
					req, err := http.NewRequest(rule.Verify.HTTPVerb, url, nil)
					if err != nil {
						fmt.Println(err)
					}
					for key, val := range headerCombination {
						req.Header.Add(key, val)
					}

					// TODO implement a retry if set with a polite backoff
					resp, err = client.Do(req)
					if err != nil {
						fmt.Println(err)
					}

					// set cache
					d.VerifyCache.Set(url, headerCombination, resp)
				}

				if !isValidStatus(resp.StatusCode, rule.Verify.ExpectedStatus) {
					continue
				} else {
					f.Verified = true
					onlyVerifiedFindings = append(onlyVerifiedFindings, f)
				}
			}
		}
	}

	if d.Verification {
		return onlyVerifiedFindings
	}

	// append verified findings to findings. Filter will remove duplicates
	return append(onlyVerifiedFindings, findings...)
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
