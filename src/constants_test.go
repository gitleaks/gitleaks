package gitleaks

import (
	"io/ioutil"
	"path"
)

const testWhitelistCommit = `
[[rules]]
description = "AWS"
regex = '''AKIA[0-9A-Z]{16}'''

[whitelist]
commits = [
  "eaeffdc65b4c73ccb67e75d96bd8743be2c85973",
]
`
const testWhitelistFile = `
[[rules]]
description = "AWS"
regex = '''AKIA[0-9A-Z]{16}'''

[whitelist]
files = [
  ".go",
]
`

const testWhitelistRegex = `
[[rules]]
description = "AWS"
regex = '''AKIA[0-9A-Z]{16}'''

[whitelist]
regexes= [
  "AKIA",
]
`

const testWhitelistRepo = `
[[rules]]
description = "AWS"
regex = '''AKIA[0-9A-Z]{16}'''

[whitelist]
repos = [
  "gronit",
]
`

const testEntropyRange = `
[[rules]]
description = "Entropy ranges"
entropies = [
  "7.5-8.0",
  "3.2-3.4",
]
`
const testBadEntropyRange = `
[[rules]]
description = "Bad entropy ranges"
entropies = [
  "8.0-3.0",
]
`
const testBadEntropyRange2 = `
[[rules]]
description = "Bad entropy ranges"
entropies = [
  "8.0-8.9",
]
`

const testEntropyLineRegexRange = `
[[rules]]
description = "test entropy regex ranges"
regex = '''(?i)key(.{0,6})?(:|=|=>|:=)'''
entropies = [
	"4.1-4.3",
]
entropyROI="line"
`

const testEntropyRegexRange = `
[[rules]]
description = "test entropy regex ranges"
regex = '''(?i)key(.{0,6})?(:|=|=>|:=)'''
entropies = [
	"4.1-4.3",
]
`

const testMDFileType = `
[[rules]]
description = "test only markdown"
filetypes = [".md"]
`

const testEntropyRegexRangeGoFilter = `
[[rules]]
description = "test entropy regex ranges"
regex = '''(?i)key(.{0,6})?(:|=|=>|:=)'''
entropies = [
	"4.1-4.3",
]
filetypes = [".go"]
entropyROI="line"
`

func testTomlLoader() string {
	tmpDir, _ := ioutil.TempDir("", "whiteListConfigs")
	ioutil.WriteFile(path.Join(tmpDir, "regex"), []byte(testWhitelistRegex), 0644)
	ioutil.WriteFile(path.Join(tmpDir, "entropyLineRegex"), []byte(testEntropyLineRegexRange), 0644)
	ioutil.WriteFile(path.Join(tmpDir, "entropyRegex"), []byte(testEntropyRegexRange), 0644)
	ioutil.WriteFile(path.Join(tmpDir, "commit"), []byte(testWhitelistCommit), 0644)
	ioutil.WriteFile(path.Join(tmpDir, "file"), []byte(testWhitelistFile), 0644)
	ioutil.WriteFile(path.Join(tmpDir, "repo"), []byte(testWhitelistRepo), 0644)
	ioutil.WriteFile(path.Join(tmpDir, "entropy"), []byte(testEntropyRange), 0644)
	ioutil.WriteFile(path.Join(tmpDir, "badEntropy"), []byte(testBadEntropyRange), 0644)
	ioutil.WriteFile(path.Join(tmpDir, "badEntropy2"), []byte(testBadEntropyRange2), 0644)
	ioutil.WriteFile(path.Join(tmpDir, "mdFiles"), []byte(testMDFileType), 0644)
	ioutil.WriteFile(path.Join(tmpDir, "entropyLineRegexGo"), []byte(testEntropyRegexRangeGoFilter), 0644)
	return tmpDir
}
