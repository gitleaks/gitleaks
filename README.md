
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

#### Commands
There are two commands you will use to detect secrets; `detect` and `protect`.
##### Detect
The `detect` command is used to scan repos, directories, and files.  This comand can be used on developer machines and in CI environments. 

When running `detect` on a git repository, gitleaks will parse the output of a `git log -p` command (you can see how this executed 
[here](https://github.com/zricethezav/gitleaks/blob/7240e16769b92d2a1b137c17d6bf9d55a8562899/git/git.go#L17-L25)). 
[`git log -p` generates patches](https://git-scm.com/docs/git-log#_generating_patch_text_with_p) which gitleaks will use to detect secrets. 
You can configure what commits `git log` will range over by using the `--log-opts` flag. `--log-opts` accepts any option for `git log -p`. 
For example, if you wanted to run gitleaks on a range of commits you could use the following command: `gitleaks --source . --log-opts="--all commitA..commitB"`. 
See the `git log` [documentation](https://git-scm.com/docs/git-log) for more information.

You can scan files and directories by using the `--no-git` option.

##### Protect
The `protect` command is used to uncommitted changes in a git repo. This command should be used on developer machines in accordance with 
[shifting left on security](https://cloud.google.com/architecture/devops/devops-tech-shifting-left-on-security). 
When running `detect` on a git repository, gitleaks will parse the output of a `git diff` command (you can see how this executed 
[here](https://github.com/zricethezav/gitleaks/blob/7240e16769b92d2a1b137c17d6bf9d55a8562899/git/git.go#L48-L49)).

**NOTE**: the `protect` command can only be used on git repos, running `protect` on files or directories will result in an error message.
