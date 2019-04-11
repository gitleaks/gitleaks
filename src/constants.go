package gitleaks

const version = "2.0.0"

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
# add rules to the rule table
[[rules]]
description = "AWS"
regex = '''AKIA[0-9A-Z]{16}'''
tags = ["key", "AWS"]
entropies = [ "3.3-4.30" ]
filetypes = [ "*.go" ]
severity = "5"

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
