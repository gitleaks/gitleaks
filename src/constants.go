package gitleaks

const version = "2.0.0"

const defaultGithubURL = "https://api.github.com/"
const defaultThreadNum = 1

// ErrExit used to signal an error during gitleaks execution
const ErrExit = 2

// LeakExit used to signal leaks present in audit
const LeakExit = 1

const defaultConfig = `
# This is a sample config file for gitleaks. You can configure gitleaks what to search for and what to whitelist.
# The output you are seeing here is the default gitleaks config. If GITLEAKS_CONFIG environment variable
# is set, gitleaks will load configurations from that path. If option --config-path is set, gitleaks will load
# configurations from that path. Gitleaks does not whitelist anything by default.

title = "gitleaks config"
[[rules]]
description = "AWS Key"
regex = '''AKIA[0-9A-Z]{16}'''
tags = ["key", "AWS"]

[[rules]]
description = "PKCS8"
regex = '''-----BEGIN PRIVATE KEY-----'''
tags = ["key", "PKCS8"]

[[rules]]
description = "RSA"
regex = '''-----BEGIN RSA PRIVATE KEY-----'''
tags = ["key", "RSA"]

[[rules]]
description = "SSH"
regex = '''-----BEGIN OPENSSH PRIVATE KEY-----'''
tags = ["key", "SSH"]

[[rules]]
description = "PGP"
regex = '''-----BEGIN PGP PRIVATE KEY BLOCK-----'''
tags = ["key", "PGP"]

[[rules]]
description = "Facebook"
regex = '''(?i)facebook(.{0,4})?['\"][0-9a-f]{32}['\"]'''
tags = ["key", "Facebook"]

[[rules]]
description = "Twitter"
regex = '''(?i)twitter(.{0,4})?['\"][0-9a-zA-Z]{35,44}['\"]'''
tags = ["key", "Twitter"]

[[rules]]
description = "Github"
regex = '''(?i)github(.{0,4})?['\"][0-9a-zA-Z]{35,40}['\"]'''
tags = ["key", "Github"]

[[rules]]
description = "Slack"
regex = '''xox[baprs]-([0-9a-zA-Z]{10,48})?'''
tags = ["key", "Slack"]

[whitelist]
files = [
  "(.*?)(jpg|gif|doc|pdf|bin)$"
]
#commits = [
#  "whitelisted-commit1",
#  "whitelisted-commit2",
#]
#repos = [
#	"whitelisted-repo"
#]
`
