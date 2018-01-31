package main

import (
	"fmt"
	"github.com/nbutton23/zxcvbn-go"
	"log"
	"os"
	"os/exec"
	"strings"
)

// checkDiff operates on a single diff between to chronological commits
func checkDiff(commit1 string, commit2 string, repoName string) []string {
	// var leakPrs bool
	// var leaks []string
	// _, seen := cache[commit1+commit2]
	// if seen {
	// 	fmt.Println("WE HAVE SEEN THIS")
	// 	return []string{}
	// }

	if err := os.Chdir(fmt.Sprintf("%s/%s", appRoot, repoName)); err != nil {
		log.Fatal(err)
	}

	cmd := exec.Command("git", "diff", commit1, commit2)
	_, err := cmd.Output()
	// fmt.Println(string(out))
	if err != nil {
		return []string{}
	}
	return []string{}

	// cache[commit1+commit2] = true
	// lines := checkRegex(string(out))
	// if len(lines) == 0 {
	// 	return []string{}
	// }
	//
	// for _, line := range lines {
	// 	leakPrs = checkEntropy(line)
	// 	if leakPrs {
	// 		leaks = append(leaks, line)
	// 	}
	// }
	// return leaks
}

// check each line of a diff and see if there are any potential secrets
// [1] https://people.eecs.berkeley.edu/~rohanpadhye/files/key_leaks-msr15.pdf
func checkRegex(diff string) []string {
	var match string
	var results []string
	lines := strings.Split(diff, "\n")
	for _, line := range lines {
		// doubtful a leak would be on a line > 120 characters
		if len(line) == 0 || len(line) > 80 {
			continue
		}
		for _, re := range regexes {
			match = re.FindString(line)
			if len(match) == 0 {
				continue
			}
			results = append(results, line)
		}
	}
	return results
}

// checkEntropy determines whether target contains enough
// entropy for a hash
// TODO remove stop words:
// setting(s), config(s), property(s), etc
func checkEntropy(target string) bool {
	index := assignRegex.FindStringIndex(target)
	if len(index) == 0 {
		return false
	}

	// TODO check for stop words here
	target = strings.Trim(target[index[1]:len(target)], " ")

	if len(target) > 70 {
		return false
	}

	// entropy := shannonEntropy(target)
	entropy := zxcvbn.PasswordStrength(target, nil).Entropy

	// tune this/make option
	if entropy > 70 {
		return true
	}
	return false
}
