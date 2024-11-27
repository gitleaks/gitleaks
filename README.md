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
	  <a href="https://github.com/gitleaks/gitleaks/actions/workflows/test.yml">
		  <img alt="Github Test" src="https://github.com/gitleaks/gitleaks/actions/workflows/test.yml/badge.svg">
	  </a>
	  <a href="https://hub.docker.com/r/zricethezav/gitleaks">
		  <img src="https://img.shields.io/docker/pulls/zricethezav/gitleaks.svg" />
	  </a>
	  <a href="https://github.com/gitleaks/gitleaks-action">
        	<img alt="gitleaks badge" src="https://img.shields.io/badge/protected%20by-gitleaks-blue">
    	 </a>
	  <a href="https://twitter.com/intent/follow?screen_name=zricethezav">
		  <img src="https://img.shields.io/twitter/follow/zricethezav?label=Follow%20zricethezav&style=social&color=blue" alt="Follow @zricethezav" />
	  </a>
  </p>
</p>

### Join our Discord! [![Discord](https://img.shields.io/discord/1102689410522284044.svg?label=&logo=discord&logoColor=ffffff&color=7389D8&labelColor=6A7EC2)](https://discord.gg/8Hzbrnkr7E)

Gitleaks is a tool for **detecting** secrets like passwords, API keys, and tokens in git repos, files, and whatever else you wanna throw at it via `stdin`.

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

Gitleaks can be installed using Homebrew, Docker, or Go. Gitleaks is also available in binary form for many popular platforms and OS types on the [releases page](https://github.com/gitleaks/gitleaks/releases). In addition, Gitleaks can be implemented as a pre-commit hook directly in your repo or as a GitHub action using [Gitleaks-Action](https://github.com/gitleaks/gitleaks-action).

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

   for a [native execution of GitLeaks](https://github.com/gitleaks/gitleaks/releases) or use the [`gitleaks-docker` pre-commit ID](https://github.com/gitleaks/gitleaks/blob/master/.pre-commit-hooks.yaml) for executing GitLeaks using the [official Docker images](#docker)

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
      --max-decode-depth int          allow recursive decoding up to this depth (default "0", no decoding is done)
      --max-target-megabytes int      files larger than this will be skipped
      --no-banner                     suppress banner
      --no-color                      turn off color for verbose output
      --redact uint[=100]             redact secrets from logs and stdout. To redact only parts of the secret just apply a percent value from 0..100. For example --redact=20 (default 100%)
  -f, --report-format string          output format (json, jsonextra, csv, junit, sarif) (default "json")
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
# https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml
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

# Int used to extract secret from regex match and used as the group that will have
# its entropy checked if `entropy` is set.
secretGroup = 3

# Float representing the minimum shannon entropy a regex group must have to be considered a secret.
entropy = 3.5

# Golang regular expression used to match paths. This can be used as a standalone rule or it can be used
# in conjunction with a valid `regex` entry.
path = '''a-file-path-regex'''

# Keywords are used for pre-regex check filtering. Rules that contain
# keywords will perform a quick string compare check to make sure the
# keyword(s) are in the content being scanned. Ideally these values should
# either be part of the identiifer or unique strings specific to the rule's regex
# (introduced in v8.6.0)
keywords = [
  "auth",
  "password",
  "token",
]

# Array of strings used for metadata and reporting purposes.
tags = ["tag","another tag"]

    # ⚠️ In v8.21.0 `[rules.allowlist]` was replaced with `[[rules.allowlists]]`.
    # This change was backwards-compatible: instances of `[rules.allowlist]` still  work.
    #
    # You can define multiple allowlists for a rule to reduce false positives.
    # A finding will be ignored if _ANY_ `[[rules.allowlists]]` matches.
    [[rules.allowlists]]
    description = "ignore commit A"
    # When multiple criteria are defined the default condition is "OR".
    # e.g., this can match on |commits| OR |paths| OR |stopwords|.
    condition = "OR"
    commits = [ "commit-A", "commit-B"]
    paths = [
      '''go\.mod''',
      '''go\.sum'''
    ]
    # note: stopwords targets the extracted secret, not the entire regex match
    # like 'regexes' does. (stopwords introduced in 8.8.0)
    stopwords = [
      '''client''',
      '''endpoint''',
    ]

    [[rules.allowlists]]
    # The "AND" condition can be used to make sure all criteria match.
    # e.g., this matches if |regexes| AND |paths| are satisfied.
    condition = "AND"
    # note: |regexes| defaults to check the _Secret_ in the finding.
    # Acceptable values for |regexTarget| are "secret" (default), "match", and "line".
    regexTarget = "match"
    regexes = [ '''(?i)parseur[il]''' ]
    paths = [ '''package-lock\.json''' ]

# You can extend a particular rule from the default config. e.g., gitlab-pat
# if you have defined a custom token prefix on your GitLab instance
[[rules]]
id = "gitlab-pat"
# all the other attributes from the default rule are inherited

    [[rules.allowlists]]
    regexTarget = "line"
    regexes = [ '''MY-glpat-''' ]

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

Refer to the default [gitleaks config](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml) for examples or follow the [contributing guidelines](https://github.com/gitleaks/gitleaks/blob/master/CONTRIBUTING.md) if you would like to contribute to the default configuration. Additionally, you can check out [this gitleaks blog post](https://blog.gitleaks.io/stop-leaking-secrets-configuration-2-3-aeed293b1fbf) which covers advanced configuration setups.

### Additional Configuration

#### gitleaks:allow

If you are knowingly committing a test secret that gitleaks will catch you can add a `gitleaks:allow` comment to that line which will instruct gitleaks
to ignore that secret. Ex:

```
class CustomClass:
    discord_client_secret = '8dyfuiRyq=vVc3RRr_edRk-fK__JItpZ'  #gitleaks:allow

```

#### .gitleaksignore

You can ignore specific findings by creating a `.gitleaksignore` file at the root of your repo. In release v8.10.0 Gitleaks added a `Fingerprint` value to the Gitleaks report. Each leak, or finding, has a Fingerprint that uniquely identifies a secret. Add this fingerprint to the `.gitleaksignore` file to ignore that specific secret. See Gitleaks' [.gitleaksignore](https://github.com/gitleaks/gitleaks/blob/master/.gitleaksignore) for an example. Note: this feature is experimental and is subject to change in the future.

#### Decoding

Sometimes secrets are encoded in a way that can make them difficult to find
with just regex. Now you can tell gitleaks to automatically find and decode
encoded text. The flag `--max-decode-depth` enables this feature (the default
value "0" means the feature is disabled by default).

Recursive decoding is supported since decoded text can also contain encoded
text.  The flag `--max-decode-depth` sets the recursion limit. Recursion stops
when there are no new segments of encoded text to decode, so setting a really
high max depth doesn't mean it will make that many passes. It will only make as
many as it needs to decode the text. Overall, decoding only minimally increases
scan times.

The findings for encoded text differ from normal findings in the following
ways:

- The location points the bounds of the encoded text
  - If the rule matches outside the encoded text, the bounds are adjusted to
    include that as well
- The match and secret contain the decoded value
- Two tags are added `decoded:<encoding>` and `decode-depth:<depth>`

Currently supported encodings:

- `base64` (both standard and base64url)

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
