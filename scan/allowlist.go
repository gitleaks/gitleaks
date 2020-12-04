package scan

import "github.com/zricethezav/gitleaks/v7/config"

func CommitAllowed(a config.AllowList, commit string) bool {
	for _, hash := range a.Commits {
		if commit == hash {
			return true
		}
	}
	return false
}

func FileAllowed(a config.AllowList, fileName string) bool {
	return anyRegexMatch(fileName, a.Files)
}

func PathAllowed(a config.AllowList, filePath string) bool {
	return anyRegexMatch(filePath, a.Paths)
}

func RegexAllowed(a config.AllowList, content string) bool {
	return anyRegexMatch(content, a.Regexes)
}

func LeakAllowed(a config.AllowList, leak Leak) bool {
	return false
}
