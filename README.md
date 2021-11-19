
```
○
│╲
│ ○
○ ░
░    gitleaks
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

Gitleaks is a SAST tool for detecting hardcoded secrets like passwords, api keys, and tokens in git repos. Gitleaks is an **easy-to-use, all-in-one solution** for detecting secrets, past or present, in your code.

### Getting Started
Gitleaks can be installed using Homebrew, Docker, or Go. Gitleaks is also available in binary form for many popular platforms and OS types on the [releases page](https://github.com/zricethezav/gitleaks/releases). In addition, Gitleaks can be implemented as a pre-commit hook directly in your repo.

##### MacOS

```bash
brew install gitleaks
```

##### Docker

Building the image after cloning the repo:
```bash
make dockerbuild
```

Using the image from DockerHub:
```bash
# To just pull the image
docker pull zricethezav/gitleaks:latest
# To run it from your cloned repo
cd to/your/repo/
docker run -v ${PWD}:/my-repo zricethezav/gitleaks:latest --source="/source" [OPTIONS]
```

##### Go
Go 1.16+ required.
```bash
GO111MODULE=on go get github.com/zricethezav/gitleaks/v8
```


##### As a pre-commit hook

See [pre-commit](https://github.com/pre-commit/pre-commit) for instructions.

Sample `.pre-commit-config.yaml`

```yaml
- repo: https://github.com/zricethezav/gitleaks
  rev: {version}
  hooks:
    - id: gitleaks
```

### Usage
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
                               2. (--source/-s)/.gitleaks.toml
                               if --config/-c is not set and no .gitleaks.toml/gitleaks.toml present
                               then .gitleaks.toml will be written to (--source/-s)/.gitleaks.toml for future use
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

