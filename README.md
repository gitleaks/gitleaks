# Gitleaks

```
┌─○───┐
│ │╲  │
│ │ ○ │
│ ○ ░ │
└─░───┘
```

<p align="left">
  <p align="left">
	  <a href="https://github.com/zricethezav/gitleaks/actions/workflows/test.yml">
		  <img alt="Github Test" src="https://github.com/zricethezav/gitleaks/actions/workflows/test.yml/badge.svg">
	  </a>
	  <a href="https://hub.docker.com/r/zricethezav/gitleaks">
		  <img src="https://img.shields.io/docker/pulls/zricethezav/gitleaks.svg" />
	  </a>
	  <a href="https://github.com/zricethezav/gitleaks-action">
        	<img alt="gitleaks badge" src="https://img.shields.io/badge/protected%20by-gitleaks-blue">
    	 </a>
	  <a href="https://twitter.com/intent/follow?screen_name=zricethezav">
		  <img src="https://img.shields.io/twitter/follow/zricethezav?label=Follow%20zricethezav&style=social&color=blue" alt="Follow @zricethezav" />
	  </a>
  </p>
</p>

### Join our Discord! [![Discord](https://img.shields.io/discord/1102689410522284044.svg?label=&logo=discord&logoColor=ffffff&color=7389D8&labelColor=6A7EC2)](https://discord.gg/8Hzbrnkr7E)

Gitleaks is a SAST tool for **detecting** and **preventing** hardcoded secrets like passwords, api keys, and tokens in git repos. Gitleaks is an **easy-to-use, all-in-one solution** for detecting secrets, past or present, in your code.

```
➜  ~/code(master) gitleaks git -v

    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks


Finding:     "export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef",
Secret:      cafebabe:deadbeef
RuleID:      sidekiq-secret
Entropy:     2.609850
File:        cmd/generate/config/rules/sidekiq.go
Line:        23
Commit:      cd5226711335c68be1e720b318b7bc3135a30eb2
Author:      John
Email:       john@users.noreply.github.com
Date:        2022-08-03T12:31:40Z
Fingerprint: cd5226711335c68be1e720b318b7bc3135a30eb2:cmd/generate/config/rules/sidekiq.go:sidekiq-secret:23
```

## Getting Started

Gitleaks can be installed using Homebrew, Docker, or Go. Gitleaks is also available in binary form for many popular platforms and OS types on the [releases page](https://github.com/zricethezav/gitleaks/releases). In addition, Gitleaks can be implemented as a pre-commit hook directly in your repo or as a GitHub action using [Gitleaks-Action](https://github.com/gitleaks/gitleaks-action).

### Installing

```bash
# MacOS
brew install gitleaks

# Docker (DockerHub)
docker pull zricethezav/gitleaks:latest
docker run -v ${path_to_host_folder_to_scan}:/path zricethezav/gitleaks:latest [COMMAND] [OPTIONS] [SOURCE_PATH]

# Docker (ghcr.io)
docker pull ghcr.io/gitleaks/gitleaks:latest
docker run -v ${path_to_host_folder_to_scan}:/path ghcr.io/gitleaks/gitleaks:latest [COMMAND] [OPTIONS] [SOURCE_PATH]

# From Source (make sure `go` is installed)
git clone https://github.com/gitleaks/gitleaks.git
cd gitleaks
make build
```

### GitHub Action

Check out the official [Gitleaks GitHub Action](https://github.com/gitleaks/gitleaks-action)

```
name: gitleaks
on: [pull_request, push, workflow_dispatch]
jobs:
  scan:
    name: gitleaks
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE}} # Only required for Organizations, not personal accounts.
```

### Pre-Commit

1. Install pre-commit from https://pre-commit.com/#install
2. Create a `.pre-commit-config.yaml` file at the root of your repository with the following content:

   ```
   repos:
     - repo: https://github.com/gitleaks/gitleaks
       rev: v8.19.0
       hooks:
         - id: gitleaks
   ```

   for a [native execution of GitLeaks](https://github.com/zricethezav/gitleaks/releases) or use the [`gitleaks-docker` pre-commit ID](https://github.com/zricethezav/gitleaks/blob/master/.pre-commit-hooks.yaml) for executing GitLeaks using the [official Docker images](#docker)

3. Auto-update the config to the latest repos' versions by executing `pre-commit autoupdate`
4. Install with `pre-commit install`
5. Now you're all set!

```
➜ git commit -m "this commit contains a secret"
Detect hardcoded secrets.................................................Failed
```

Note: to disable the gitleaks pre-commit hook you can prepend `SKIP=gitleaks` to the commit command
and it will skip running gitleaks

```
➜ SKIP=gitleaks git commit -m "skip gitleaks check"
Detect hardcoded secrets................................................Skipped
```

## Usage

```
Usage:
  gitleaks [command]

Available Commands:
  completion  generate the autocompletion script for the specified shell
  dir         scan directories or files for secrets
  git         scan git repositories for secrets
  help        Help about any command
  stdin       detect secrets from stdin
  version     display gitleaks version

Flags:
  -b, --baseline-path string          path to baseline with issues that can be ignored
  -c, --config string                 config file path
                                      order of precedence:
                                      1. --config/-c
                                      2. env var GITLEAKS_CONFIG
                                      3. (target path)/.gitleaks.toml
                                      If none of the three options are used, then gitleaks will use the default config
      --enable-rule strings           only enable specific rules by id
      --exit-code int                 exit code when leaks have been encountered (default 1)
  -i, --gitleaks-ignore-path string   path to .gitleaksignore file or folder containing one (default ".")
  -h, --help                          help for gitleaks
      --ignore-gitleaks-allow         ignore gitleaks:allow comments
  -l, --log-level string              log level (trace, debug, info, warn, error, fatal) (default "info")
      --max-target-megabytes int      files larger than this will be skipped
      --no-banner                     suppress banner
      --no-color                      turn off color for verbose output
      --redact uint[=100]             redact secrets from logs and stdout. To redact only parts of the secret just apply a percent value from 0..100. For example --redact=20 (default 100%)
  -f, --report-format string          output format (json, csv, junit, sarif) (default "json")
  -r, --report-path string            report file
  -v, --verbose                       show verbose output from scan
      --version                       version for gitleaks

Use "gitleaks [command] --help" for more information about a command.
```

### Commands

⚠️ v8.19.0 introduced a change that deprecated `detect` and `protect`. Those commands are still available but
are hidden in the `--help` menu. Take a look at this [gist](https://gist.github.com/zricethezav/b325bb93ebf41b9c0b0507acf12810d2) for easy command translations.
If you find v8.19.0 broke an existing command (`detect`/`protect`), please open an issue.

There are three scanning modes: `git`, `dir`, and `stdin`.

#### Git
The `git` command lets you scan local git repos. Under the hood, gitleaks uses the `git log -p` command to scan patches.
You can configure the behavior of `git log -p` with the `log-opts` option.
For example, if you wanted to run gitleaks on a range of commits you could use the following
command: `gitleaks git -v --log-opts="--all commitA..commitB" path_to_repo`. See the [git log](https://git-scm.com/docs/git-log) documentation for more information.
If there is no target specified as a positional argument, then gitleaks will attempt to scan the current working directory as a git repo.

#### Dir
The `dir` (aliases include `files`, `directory`) command lets you scan directories and files. Example: `gitleaks dir -v path_to_directory_or_file`.
If there is no target specified as a positional argument, then gitleaks will scan the current working directory.

#### Stdin
You can also stream data to gitleaks with the `stdin` command. Example: `cat some_file | gitleaks -v stdin`

### Creating a baseline

When scanning large repositories or repositories with a long history, it can be convenient to use a baseline. When using a baseline,
gitleaks will ignore any old findings that are present in the baseline. A baseline can be any gitleaks report. To create a gitleaks report, run gitleaks with the `--report-path` parameter.

```
gitleaks git --report-path gitleaks-report.json # This will save the report in a file called gitleaks-report.json
```

Once as baseline is created it can be applied when running the detect command again:

```
gitleaks git --baseline-path gitleaks-report.json --report-path findings.json
```

After running the detect command with the --baseline-path parameter, report output (findings.json) will only contain new issues.

## Pre-Commit hook

You can run Gitleaks as a pre-commit hook by copying the example `pre-commit.py` script into
your `.git/hooks/` directory.

## Configuration

Gitleaks offers a configuration format you can follow to write your own secret detection rules:

```toml
# Title for the gitleaks configuration file.
title = "Gitleaks title"

# Extend the base (this) configuration. When you extend a configuration
# the base rules take precedence over the extended rules. I.e., if there are
# duplicate rules in both the base configuration and the extended configuration
# the base rules will override the extended rules.
# Another thing to know with extending configurations is you can chain together
# multiple configuration files to a depth of 2. Allowlist arrays are appended
# and can contain duplicates.
# useDefault and path can NOT be used at the same time. Choose one.
[extend]
# useDefault will extend the base configuration with the default gitleaks config:
# https://github.com/zricethezav/gitleaks/blob/master/config/gitleaks.toml
useDefault = true
# or you can supply a path to a configuration. Path is relative to where gitleaks
# was invoked, not the location of the base config.
path = "common_config.toml"

# An array of tables that contain information that define instructions
# on how to detect secrets
[[rules]]

# Unique identifier for this rule
id = "awesome-rule-1"

# Short human readable description of the rule.
description = "awesome rule 1"

# Golang regular expression used to detect secrets. Note Golang's regex engine
# does not support lookaheads.
regex = '''one-go-style-regex-for-this-rule'''

# Golang regular expression used to match paths. This can be used as a standalone rule or it can be used
# in conjunction with a valid `regex` entry.
path = '''a-file-path-regex'''

# Array of strings used for metadata and reporting purposes.
tags = ["tag","another tag"]

# Int used to extract secret from regex match and used as the group that will have
# its entropy checked if `entropy` is set.
secretGroup = 3

# Float representing the minimum shannon entropy a regex group must have to be considered a secret.
entropy = 3.5

# Keywords are used for pre-regex check filtering. Rules that contain
# keywords will perform a quick string compare check to make sure the
# keyword(s) are in the content being scanned. Ideally these values should
# either be part of the idenitifer or unique strings specific to the rule's regex
# (introduced in v8.6.0)
keywords = [
  "auth",
  "password",
  "token",
]

# Report is a boolean that controls whether or not the rule will be included in stdout and the report output.
# The default is true. This field is useful for matching supplemental credentials for verification, like client-ids. 
# ️(introduced in v8.20.0) 
report = true

# You can include an allowlist table for a single rule to reduce false positives or ignore commits
# with known/rotated secrets
[rules.allowlist]
description = "ignore commit A"
commits = [ "commit-A", "commit-B"]
paths = [
  '''go\.mod''',
  '''go\.sum'''
]
# note: (rule) regexTarget defaults to check the _Secret_ in the finding.
# if regexTarget is not specified then _Secret_ will be used.
# Acceptable values for regexTarget are "match" and "line"
regexTarget = "match"
regexes = [
  '''process''',
  '''getenv''',
]
# note: stopwords targets the extracted secret, not the entire regex match
# like 'regexes' does. (stopwords introduced in 8.8.0)
stopwords = [
  '''client''',
  '''endpoint''',
]

# ⚠️ rules.verify is an experimental feature introduced in 8.20.0 and subject to change! ⚠️ 
# You can include a verify table for a single rule to verify the secret with a remote service.
# The the gitleaks engine will substitute a matched secret from the parent rule with a placeholder where the
# placeholder is located. Placeholder(s) can be used in the `url`, `headers`, and `body` fields.
# The placeholder syntax is ${rule-id}. You can use multiple placeholders targeting different rules, 
# e.g, `headers = {Authorization = "Bearer ${rule-1}:${rule-2}}.` 
# If you use multiple placeholders and one of the placeholders is targeting a rule that matches supplemental credentials, like a client-id, you can 
# silence the reported of that supplemental credential by setting `report=false` on the supplemental credential rule.
[rules.verify]
# The HTTP method used for the verification request.
# Methods include GET, POST, HEAD.
httpVerb = "GET"
# The URL to which the request will be sent. In this case, the detected. 
# If a placeholder is present, a matched secret will be substituted for the placeholder.
url = "https://example.com/verify"
# A table defining any headers that should be sent with the request.
# In this case, we are using the detected secret as a bearer token in 
# the Authorization header. The placeholder ${awesome-rule-1} will be
# replaced by the actual secret detected by the rule.
headers = {Authorization = "Bearer ${awesome-rule-1}"}
# A list of expected HTTP status codes. If the verification response 
# matches one of these statuses, the secret will be considered valid.
# Can be used in conjunction with `expectedBodyContains`.
expectedStatus = [
  200,  # HTTP 200 OK status is expected for valid secrets
]
# A list of strings that are expected to appear in the body of the HTTP 
# response. If any of these strings are found in the response body, the secret will be considered valid. Can be used in conjunction with `expectedStatus`.
expectedBodyContains = [
  '''success''',  # The response should contain "success" to confirm validity
]


# This is a global allowlist which has a higher order of precedence than rule-specific allowlists.
# If a commit listed in the `commits` field below is encountered then that commit will be skipped and no
# secrets will be detected for said commit. The same logic applies for regexes and paths.
[allowlist]
description = "global allow list"
commits = [ "commit-A", "commit-B", "commit-C"]
paths = [
  '''gitleaks\.toml''',
  '''(.*?)(jpg|gif|doc)'''
]

# note: (global) regexTarget defaults to check the _Secret_ in the finding.
# if regexTarget is not specified then _Secret_ will be used.
# Acceptable values for regexTarget are "match" and "line"
regexTarget = "match"

regexes = [
  '''219-09-9999''',
  '''078-05-1120''',
  '''(9[0-9]{2}|666)-\d{2}-\d{4}''',
]
# note: stopwords targets the extracted secret, not the entire regex match
# like 'regexes' does. (stopwords introduced in 8.8.0)
stopwords = [
  '''client''',
  '''endpoint''',
]
```

Refer to the default [gitleaks config](https://github.com/zricethezav/gitleaks/blob/master/config/gitleaks.toml) for examples or follow the [contributing guidelines](https://github.com/gitleaks/gitleaks/blob/master/CONTRIBUTING.md) if you would like to contribute to the default configuration. Additionally, you can check out [this gitleaks blog post](https://blog.gitleaks.io/stop-leaking-secrets-configuration-2-3-aeed293b1fbf) which covers advanced configuration setups.

### Verification (⚠️ experimental feature added in v8.20.0)
When a secret is detected based on a rule that includes a `verify` section, Gitleaks will send an HTTP request to a defined URL, substituting the secret into placeholders in the request. The response status and body are then checked against expected values to determine if the secret is valid.

Example configuration w/ `rules.verify` set

```toml
[[rules]]
id = "github-pat"
description = "Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure."
regex = '''ghp_[0-9a-zA-Z]{36}'''
entropy = 3
keywords = [
    "ghp_",
]
[rules.verify]
httpVerb = "GET"
url = "https://api.github.com/user"
headers = {Accept = "application/vnd.github+json", Authorization = "Bearer ${github-pat}", X-GitHub-Api-Version = "2022-11-28"}
expectedStatus = [
    200,
]
```
In the above example, Gitleaks will:
- Detect any GitHub Personal Access Tokens matching the regex pattern.
- Verify the token by sending a GET request to https://api.github.com/user with the detected token included in the Authorization header.
- Check if the HTTP response status is 200 and confirm that the token is valid.

Gitleaks' verify feature supports helper functions within placeholders to manipulate secret values before they are substituted into the request. The supported helper functions are:

- Base64 Encoding: ${base64("string")} encodes the specified string using Base64 encoding.
- URL Encoding: ${urlEncode("string")} encodes the specified string for safe inclusion in a URL query parameter.

```
headers = {
    Authorization = "Basic ${base64("${rule-to-capture-username}:${rule-to-capture-password}")}",
}
```

When using multiple placeholders in the verify section, Gitleaks will generate all possible combinations (cartesian product) of the secrets detected for the specified rules. This ensures that all combinations are tested for validity, which is particularly useful when a valid secret is composed of multiple parts.

```toml
[[rules]]
id = "client-id"
description = "OAuth Client ID"
regex = '''client_id_[0-9a-zA-Z]{10}'''
keywords = ["client_id"]
report = false  # Suppress individual reporting

[[rules]]
id = "client-secret"
description = "OAuth Client Secret"
regex = '''client_secret_[0-9a-zA-Z]{20}'''
keywords = ["client_secret"]
[rules.verify]
httpVerb = "POST"
url = "https://api.example.com/oauth/token"
headers = {
    Content-Type = "application/x-www-form-urlencoded",
}
body = '''
{
  client_id="${client-id}",
  client_secret="${client-secret}"
}
'''
expectedStatus = [
  200,
]
```

In this example:

- Detect both client-id and client-secret.
- Combine them in the body of the verification request using placeholders.
- Gitleaks will generate all combinations of detected client-id and client-secret values.

Note: If multiple `client-ids` and `client-secrets` are detected, Gitleaks will attempt to verify each possible pair.

Some limitations and best practices when using Gitleaks' verify rules:
- Max Combinations Threshold: Gitleaks may limit the number of combinations to prevent excessive requests (e.g., skipping if more than 3 secrets per rule).
- Suppression of Individual Findings: Use report = false on supplemental credential rules (like client-id) to avoid cluttering reports with partial un-verified secrets.
- Error Handling: If verification fails due to too many combinations or missing required secrets, Gitleaks will skip verification for that finding and provide a status reason.
</details>


### Additional Configuration

#### gitleaks:allow

If you are knowingly committing a test secret that gitleaks will catch you can add a `gitleaks:allow` comment to that line which will instruct gitleaks
to ignore that secret. Ex:

```
class CustomClass:
    discord_client_secret = '8dyfuiRyq=vVc3RRr_edRk-fK__JItpZ'  #gitleaks:allow

```

#### .gitleaksignore

You can ignore specific findings by creating a `.gitleaksignore` file at the root of your repo. In release v8.10.0 Gitleaks added a `Fingerprint` value to the Gitleaks report. Each leak, or finding, has a Fingerprint that uniquely identifies a secret. Add this fingerprint to the `.gitleaksignore` file to ignore that specific secret. See Gitleaks' [.gitleaksignore](https://github.com/zricethezav/gitleaks/blob/master/.gitleaksignore) for an example. Note: this feature is experimental and is subject to change in the future.

## Sponsorships
<p align="left">
	<h3><a href="https://coderabbit.ai/?utm_source=oss&utm_medium=sponsorship&utm_campaign=gitleaks">coderabbit.ai</h3>
	  <a href="https://coderabbit.ai/?utm_source=oss&utm_medium=sponsorship&utm_campaign=gitleaks">
		  <img alt="CodeRabbit.ai Sponsorship" src="https://github.com/gitleaks/gitleaks/assets/15034943/76c30a85-887b-47ca-9956-17a8e55c6c41" width=200>
	  </a>
</p>
<p align="left">
	  <a href="https://www.tines.com/?utm_source=oss&utm_medium=sponsorship&utm_campaign=gitleaks">
		  <img alt="Tines Sponsorship" src="https://user-images.githubusercontent.com/15034943/146411864-4878f936-b4f7-49a0-b625-f9f40c704bfa.png" width=200>
	  </a>
  </p>


## Exit Codes

You can always set the exit code when leaks are encountered with the --exit-code flag. Default exit codes below:

```
0 - no leaks present
1 - leaks or error encountered
126 - unknown flag
```
