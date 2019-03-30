package gitleaks

const version = "1.25.0"

const defaultGithubURL = "https://api.github.com/"
const defaultThreadNum = 1
const ErrExit = 2
const LeakExit = 1

const defaultConfig = `
# This is a sample config file for gitleaks. You can configure gitleaks what to search for and what to whitelist.
# The output you are seeing here is the default gitleaks config. If GITLEAKS_CONFIG environment variable
# is set, gitleaks will load configurations from that path. If option --config-path is set, gitleaks will load
# configurations from that path. Gitleaks does not whitelist anything by default.

title = "gitleaks config"
# add regexes to the regex table
[[regexes]]
description = "AWS"
regex = '''AKIA[0-9A-Z]{16}'''
[[regexes]]
description = "PKCS8"
regex = '''-----BEGIN PRIVATE KEY-----'''
[[regexes]]
description = "RSA"
regex = '''-----BEGIN RSA PRIVATE KEY-----'''
[[regexes]]
description = "SSH"
regex = '''-----BEGIN OPENSSH PRIVATE KEY-----'''
[[regexes]]
description = "PGP"
regex = '''-----BEGIN PGP PRIVATE KEY BLOCK-----'''
[[regexes]]
description = "Facebook"
regex = '''(?i)facebook(.{0,4})?['\"][0-9a-f]{32}['\"]'''
[[regexes]]
description = "Twitter"
regex = '''(?i)twitter(.{0,4})?['\"][0-9a-zA-Z]{35,44}['\"]'''
[[regexes]]
description = "Github"
regex = '''(?i)github(.{0,4})?['\"][0-9a-zA-Z]{35,40}['\"]'''
[[regexes]]
description = "Slack"
regex = '''xox[baprs]-([0-9a-zA-Z]{10,48})?'''

[entropy]
lineregexes = [
	"api",
	"key",
	"signature",
	"secret",
	"password",
	"pass",
	"pwd",
	"token",
	"curl",
	"wget",
	"https?",
]

[whitelist]
files = [
  "(.*?)(jpg|gif|doc|pdf|bin)$"
]
#commits = [
#  "BADHA5H1",
#  "BADHA5H2",
#]
#repos = [
#	"mygoodrepo"
#]
[misc]
#entropy = [
#	"3.3-4.30"
#	"6.0-8.0
#]
`
