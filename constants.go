package main

const version = "1.2.2"
const defaultGithubURL = "https://api.github.com/"
const defaultConfig = `
title = "gitleaks config"
# add regexes to the regex table
[[regexes]]
description = "AWS"
regex = '''AKIA[0-9A-Z]{16}'''
[[regexes]]
description = "RKCS8"
regex = '''-----BEGIN PRIVATE KEY-----'''
[[regexes]]
description = "RSA"
regex = '''-----BEGIN RSA PRIVATE KEY-----'''
[[regexes]]
description = "Github"
regex = '''(?i)github.*['\"][0-9a-zA-Z]{35,40}['\"]'''
[[regexes]]
description = "SSH"
regex = '''-----BEGIN OPENSSH PRIVATE KEY-----'''
[[regexes]]
description = "Facebook"
regex = '''(?i)facebook.*['\"][0-9a-f]{32}['\"]'''
[[regexes]]
description = "Twitter"
regex = '''(?i)twitter.*['\"][0-9a-zA-Z]{35,44}['\"]'''
#[[regexes]]
#description = "URI credentials"
#regex = '''(https|http|ftp)://(.+):(.+)@(.+)'''

[whitelist]

#regexes = [
#  "AKAIMYFAKEAWKKEY",
#]

#files = [
#  "(.*?)(jpg|gif|doc|pdf|bin)$"
#]

#commits = [
#  "BADHA5H1",
#  "BADHA5H2",
#]

#branches = [
#	"dev/STUPDIFKNFEATURE"
#]
`
