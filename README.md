# gitleaks
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
	  <a href="https://twitter.com/intent/follow?screen_name=zricethezav">
		  <img src="https://img.shields.io/twitter/follow/zricethezav?label=Follow%20zricethezav&style=social&color=blue" alt="Follow @zricethezav" />
	  </a>
  </p>
</p>

Gitleaks is a SAST tool for **detecting** and **preventing** hardcoded secrets like passwords, api keys, and tokens in git repos. Gitleaks is an **easy-to-use, all-in-one solution** for detecting secrets, past or present, in your code.

[![asciicast](https://asciinema.org/a/455683.svg)](https://asciinema.org/a/455683)

## Getting Started
Gitleaks can be installed using Homebrew, Docker, or Go. Gitleaks is also available in binary form for many popular platforms and OS types on the [releases page](https://github.com/zricethezav/gitleaks/releases). In addition, Gitleaks can be implemented as a pre-commit hook directly in your repo.

### MacOS

```bash
brew install gitleaks
```

### Docker
#### DockerHub
```bash
docker pull zricethezav/gitleaks:latest
docker run -v ${path_to_host_folder_to_scan}:/path zricethezav/gitleaks:latest [COMMAND] --source="/path" [OPTIONS]
```
#### ghcr.io
```bash
docker pull ghcr.io/zricethezav/gitleaks:latest
docker run -v ${path_to_host_folder_to_scan}:/path zricethezav/gitleaks:latest [COMMAND] --source="/path" [OPTIONS]
```

### From Source
1. Download and install Go from https://golang.org/dl/
2. Clone the repo
```bash
git clone https://github.com/zricethezav/gitleaks.git
```
3. Build the binary
```bash
cd gitleaks
make build
```

### Pre-Commit
1. Install pre-commit from https://pre-commit.com/#install
2. Create a `.pre-commit-config.yaml` file at the root of your repository with the following content:
   ```
   repos:
     - repo: https://github.com/zricethezav/gitleaks
       rev: v8.2.0
       hooks:
         - id: gitleaks
   ```
   for a [native execution of GitLeaks](https://github.com/zricethezav/gitleaks/releases) or use the [`gitleaks-docker` pre-commit ID](https://github.com/zricethezav/gitleaks/blob/master/.pre-commit-hooks.yaml) for executing GitLeaks using the [official Docker images](#docker)

3. Install with `pre-commit install`
4. Now you're all set!
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
  detect      Detect secrets in code
  help        Help about any command
  protect     Protect secrets in code
  version     Display gitleaks version

Flags:
  -c, --config string          config file path
                               order of precedence:
                               1. --config/-c
                               2. env var GITLEAKS_CONFIG
                               3. (--source/-s)/.gitleaks.toml
                               If none of the three options are used, then gitleaks will use the default config
      --exit-code string       exit code when leaks have been encountered (default: 1)
  -h, --help                   help for gitleaks
  -l, --log-level string       log level (debug, info, warn, error, fatal) (default "info")
      --redact                 redact secrets from logs and stdout
  -f, --report-format string   output format (json, csv, sarif)
  -r, --report-path string     report file
  -s, --source string          path to source (git repo, directory, file)
  -v, --verbose                show verbose output from scan

Use "gitleaks [command] --help" for more information about a command.
```

### Commands
There are two commands you will use to detect secrets; `detect` and `protect`.
#### Detect
The `detect` command is used to scan repos, directories, and files.  This command can be used on developer machines and in CI environments.

When running `detect` on a git repository, gitleaks will parse the output of a `git log -p` command (you can see how this executed
[here](https://github.com/zricethezav/gitleaks/blob/7240e16769b92d2a1b137c17d6bf9d55a8562899/git/git.go#L17-L25)).
[`git log -p` generates patches](https://git-scm.com/docs/git-log#_generating_patch_text_with_p) which gitleaks will use to detect secrets.
You can configure what commits `git log` will range over by using the `--log-opts` flag. `--log-opts` accepts any option for `git log -p`.
For example, if you wanted to run gitleaks on a range of commits you could use the following command: `gitleaks --source . --log-opts="--all commitA..commitB"`.
See the `git log` [documentation](https://git-scm.com/docs/git-log) for more information.

You can scan files and directories by using the `--no-git` option.

#### Protect
The `protect` command is used to uncommitted changes in a git repo. This command should be used on developer machines in accordance with
[shifting left on security](https://cloud.google.com/architecture/devops/devops-tech-shifting-left-on-security).
When running `protect` on a git repository, gitleaks will parse the output of a `git diff` command (you can see how this executed
[here](https://github.com/zricethezav/gitleaks/blob/7240e16769b92d2a1b137c17d6bf9d55a8562899/git/git.go#L48-L49)). You can set the
`--staged` flag to check for changes in commits that have been `git add`ed. The `--staged` flag should be used when running Gitleaks
as a pre-commit.

**NOTE**: the `protect` command can only be used on git repos, running `protect` on files or directories will result in an error message.

### Verify Findings
You can verify a finding found by gitleaks using a `git log` command.
Example output:
```
{
        "Description": "AWS",
        "StartLine": 37,
        "EndLine": 37,
        "StartColumn": 19,
        "EndColumn": 38,
        "Match": "\t\t\"aws_secret= \\\"AKIAIMNOJVGFDXXXE4OA\\\"\":          true,",
        "Secret": "AKIAIMNOJVGFDXXXE4OA",
        "File": "checks_test.go",
        "Commit": "ec2fc9d6cb0954fb3b57201cf6133c48d8ca0d29",
        "Entropy": 0,
        "Author": "zricethezav",
        "Email": "thisispublicanyways@gmail.com",
        "Date": "2018-01-28 17:39:00 -0500 -0500",
        "Message": "[update] entropy check",
        "Tags": [],
        "RuleID": "aws-access-token"
}

```
We can use the following format to verify the leak:

```
git log -L {StartLine,EndLine}:{File} {Commit}
```
So in this example it would look like:
```
git log -L 37,37:checks_test.go ec2fc9d6cb0954fb3b57201cf6133c48d8ca0d29
```
Which gives us:

```
commit ec2fc9d6cb0954fb3b57201cf6133c48d8ca0d29
Author: zricethezav <thisispublicanyways@gmail.com>
Date:   Sun Jan 28 17:39:00 2018 -0500

    [update] entropy check

diff --git a/checks_test.go b/checks_test.go
--- a/checks_test.go
+++ b/checks_test.go
@@ -28,0 +37,1 @@
+               "aws_secret= \"AKIAIMNOJVGFDXXXE4OA\"":          true,

```

## Pre-Commit hook
You can run Gitleaks as a pre-commit hook by copying the example `pre-commit.py` script into
your `.git/hooks/` directory.

## Configuration
Gitleaks offers a configuration format you can follow to write your own secret detection rules:
```toml
# Title for the gitleaks configuration file.
title = "Gitleaks title"

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

# You can include an allowlist table for a single rule to reduce false positives or ignore commits
# with known/rotated secrets
[rules.allowlist]
description = "ignore commit A"
commits = [ "commit-A", "commit-B"]
paths = [
	'''go\.mod''',
	'''go\.sum'''
]
regexes = [
   	'''process''',
	'''getenv''',
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
regexes = [
    	'''219-09-9999''',
    	'''078-05-1120''',
    	'''(9[0-9]{2}|666)-\d{2}-\d{4}''',
]
```
Refer to the default [gitleaks config](https://github.com/zricethezav/gitleaks/blob/master/config/gitleaks.toml) for examples and advice on writing regular expressions for secret detection.



## Sponsorships
<p align="left">
	  <a href="https://www.tines.com/?utm_source=oss&utm_medium=sponsorship&utm_campaign=gitleaks">
		  <img alt="Tines Sponsorship" src="https://user-images.githubusercontent.com/15034943/146411864-4878f936-b4f7-49a0-b625-f9f40c704bfa.png" width=200>
	  </a>
	  </p>
	  <a href="https://www.typeform.com/">
		  <img src="https://user-images.githubusercontent.com/15034943/146945294-a6473d55-86b8-4f53-941e-7f185ad6b3d7.png" width=200/>
	  </a>
  </p>




## Exit Codes
You can always set the exit code when leaks are encountered with the --exit-code flag. Default exit codes below:
```
0 - no leaks present
1 - leaks or error encountered
126 - unknown flag
```
