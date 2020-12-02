<p align="center">
  <img alt="gitleaks" src="https://raw.githubusercontent.com/zricethezav/gifs/master/gitleakslogo.png" height="70" />
  <p align="center">
      <a href="https://travis-ci.org/zricethezav/gitleaks"><img alt="Travis" src="https://img.shields.io/travis/zricethezav/gitleaks/master.svg?style=flat-square"></a>
  </p>
</p>

Gitleaks is a SAST tool for detecting hardcoded secrets like passwords, api keys, and tokens in git repos. Gitleaks aims to be the **easy-to-use, all-in-one solution** for finding secrets, past or present, in your code. 
 
### Features:
- Scan for [commited](https://github.com/zricethezav/gitleaks/wiki/Scanning) secrets
- Scan for [uncommitted](https://github.com/zricethezav/gitleaks/wiki/Scanning#uncommitted-changes-scan) secrets as part of shifting security left
- Scan for entire directories and files
- Available [Github Action](https://github.com/marketplace/actions/gitleaks)
- [Custom rules](https://github.com/zricethezav/gitleaks/wiki/Configuration) via toml configuration
- High performance using [go-git](https://github.com/go-git/go-git)
- JSON, SARIF, and CSV reporting
- Private repo scans using key or password based authentication


### Installation
Written in Go, gitleaks is available in binary form for many popular platforms and OS types from the [releases page](https://github.com/zricethezav/gitleaks/releases). Alternatively, executed via Docker or it can be installed using Go directly.

##### MacOS

```
brew install gitleaks
```

##### Docker

```bash
docker pull zricethezav/gitleaks
```

##### Go
```bash
GO111MODULE=on go get github.com/zricethezav/gitleaks/v7
```

### Usage and Options
```
Usage:
  gitleaks [OPTIONS]

Application Options:
  -v, --verbose           Show verbose output from scan
  -r, --repo-url=         Repository URL
  -p, --path=             Path to directory (repo if contains .git) or file
  -c, --config-path=      Path to config
      --repo-config-path= Path to gitleaks config relative to repo root
      --clone-path=       Path to clone repo to disk
      --clone-cleanup=    Deletes cloned repo after scan
      --version           Version number
      --username=         Username for git repo
      --password=         Password for git repo
      --access-token=     Access token for git repo
      --threads=          Maximum number of threads gitleaks spawns
      --ssh-key=          Path to ssh key used for auth
      --unstaged          Run gitleaks on unstaged code
      --branch=           Branch to scan
      --redact            Redact secrets from log messages and leaks
      --debug             Log debug messages
      --no-git            Treat git repos as plain directories and scan those
                          files
  -o, --report=           Report output path
  -f, --format=           JSON, CSV, SARIF (default: json)
      --files-at-commit=  Sha of commit to scan all files at commit
      --commit=           Sha of commit to scan or "latest" to scan the last
                          commit of the repository
      --commits=          Comma separated list of a commits to scan
      --commits-file=     Path to file of line separated list of commits to scan
      --commit-from=      Commit to start scan from
      --commit-to=        Commit to stop scan
      --commit-since=     Scan commits more recent than a specific date. Ex:
                          '2006-01-02' or '2006-01-02T15:04:05-0700' format.
      --commit-until=     Scan commits older than a specific date. Ex:
                          '2006-01-02' or '2006-01-02T15:04:05-0700' format.
      --depth=            Number of commits to scan

Help Options:
  -h, --help              Show this help message
```


###  Sponsors ❤️
#### Corporate Sponsors
[![gammanet](https://gammanet.com/assets/images/new-design/gamma-logo.png)](https://gammanet.com/?utm_source=gitleaks&utm_medium=homepage&utm_campaign=gitleaks_promotion)

Gamma proactively detects and remediates data leaks across cloud apps. Scan your public repos for secret leaks with [Gamma](https://gammanet.com/github-demo?utm_source=gitleaks&utm_medium=homepage&utm_campaign=gitleaks_promotion)

#### Individual Sponsors 
These users are [sponsors](https://github.com/sponsors/zricethezav) of gitleaks:

[![Adam Shannon](https://github.com/adamdecaf.png?size=50)](https://github.com/adamdecaf) | 
---|
----


#### Logo Attribution
The Gitleaks logo uses the Git Logo created <a href="https://twitter.com/jasonlong">Jason Long</a> is licensed under the <a href="https://creativecommons.org/licenses/by/3.0/">Creative Commons Attribution 3.0 Unported License</a>.

