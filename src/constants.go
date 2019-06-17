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
# is set, gitleaks will load configurations from that path. If option --config is set, gitleaks will load
# configurations from that path. Gitleaks does not whitelist anything by default.

title = "gitleaks config"
[[rules]]
description = "AWS Key"
regex = '''AKIA[0-9A-Z]{16}'''
tags = ["key", "AWS"]
severity = "high"

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

[[rules]]
description = "EC"
regex = '''-----BEGIN EC PRIVATE KEY-----'''
tags = ["key", "EC"]

[[rules]]
description = "AWS MWS key"
regex = '''amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'''
tags = ["key", "AWS", "MWS"]

[[rules]]
description = "Facebook access token"
regex = '''EAACEdEose0cBA[0-9A-Za-z]+'''
tags = ["key", "Facebook"]

[[rules]]
description = "Generic API key"
regex = '''[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|"][0-9a-zA-Z]{32,45}['|"]'''
tags = ["key", "API", "generic"]

[[rules]]
description = "Generic Secret"
regex = '''[s|S][e|E][c|C][r|R][e|E][t|T].*['|"][0-9a-zA-Z]{32,45}['|"]'''
tags = ["key", "Secret", "generic"]

[[rules]]
description = "Google API key"
regex = '''AIza[0-9A-Za-z\\-_]{35}'''
tags = ["key", "Google"]

[[rules]]
description = "Google OAuth"
regex = '''[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'''
tags = ["key", "Google", "OAuth"]

[[rules]]
description = "Google OAuth access token"
regex = '''ya29\.[0-9A-Za-z\-_]+'''
tags = ["key", "Google", "OAuth"]

[[rules]]
description = "Heroku API key"
regex = '''[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}'''
tags = ["key", "Heroku"]

[[rules]]
description = "MailChimp API key"
regex = '''[0-9a-f]{32}-us[0-9]{1,2}'''
tags = ["key", "Mailchimp"]

[[rules]]
description = "Mailgun API key"
regex = '''key-[0-9a-zA-Z]{32}'''
tags = ["key", "Mailgun"]

[[rules]]
description = "Password in URL"
regex = '''[a-zA-Z]{3,10}:\/\/[^\/\s:@]{3,20}:[^\/\s:@]{3,20}@.{1,100}\/?.?'''
tags = ["key", "URL", "generic"]

[[rules]]
description = "PayPal Braintree access token"
regex = '''access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'''
tags = ["key", "Paypal"]

[[rules]]
description = "Picatic API key"
regex = '''sk_live_[0-9a-z]{32}'''
tags = ["key", "Picatic"]

[[rules]]
description = "Slack Webhook"
regex = '''https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}'''
tags = ["key", "slack"]

[[rules]]
description = "Stripe API key"
regex = '''[sk|rk]_live_[0-9a-zA-Z]{24}'''
tags = ["key", "Stripe"]

[[rules]]
description = "Square access token"
regex = '''sq0atp-[0-9A-Za-z\-_]{22}'''
tags = ["key", "square"]

[[rules]]
description = "Square OAuth secret"
regex = '''sq0csp-[0-9A-Za-z\\-_]{43}'''
tags = ["key", "square"]

[[rules]]
description = "Twilio API key"
regex = '''SK[0-9a-fA-F]{32}'''
tags = ["key", "twilio"]

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
