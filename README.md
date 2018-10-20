<p align="center">
  <img alt="gitleaks" src="https://raw.githubusercontent.com/zricethezav/gifs/master/gitleaks5.png" height="140" />
  <p align="center">
      <a href="https://travis-ci.org/zricethezav/gitleaks"><img alt="Travis" src="https://img.shields.io/travis/zricethezav/gitleaks/master.svg?style=flat-square"></a>
  </p>
</p>

## Audit git repos for secrets
### Powered by src-d's [go-git](https://github.com/src-d/go-git)
<p align="center">
    <img src="https://cdn.rawgit.com/zricethezav/5bf8259b7fea0170becffc06b8588edb/raw/f762769fe20ef3669bff34612b1bede6457631e6/termtosvg_je8bp82s.svg">
</p>

#### Installing

```bash
go get -u github.com/zricethezav/gitleaks
```
Or download from release binaries [here](https://github.com/zricethezav/gitleaks/releases)


#### Usage and Options
```
Usage:
  gitleaks [OPTIONS]

Application Options:
  -r, --repo=          Repo url to audit
      --github-user=   Github user to audit
      --github-org=    Github organization to audit
      --github-url=    GitHub API Base URL, use for GitHub Enterprise. Example: https://github.example.com/api/v3/ (default: https://api.github.com/)
      --github-pr=     Github PR url to audit. This does not clone the repo. GITHUB_TOKEN must be set
  -p, --private        Include private repos in audit
  -b, --branch=        branch name to audit (defaults to HEAD)
  -c, --commit=        sha of commit to stop at
      --depth=         maximum commit depth
      --repo-path=     Path to repo
      --owner-path=    Path to owner directory (repos discovered)
      --max-go=        Maximum number of concurrent go-routines gitleaks spawns
      --disk           Clones repo(s) to disk
      --all-refs       run audit on all refs
      --single-search= single regular expression to search for
      --config=        path to gitleaks config
      --ssh-key=       path to ssh key
      --exclude-forks  exclude forks for organization/user audits
  -e, --entropy=       Include entropy checks during audit. Entropy scale: 0.0(no entropy) - 8.0(max entropy)
  -l, --log=           log level
  -v, --verbose        Show verbose output from gitleaks audit
      --report=        path to write report file
      --redact         redact secrets from log messages and report
      --version        version number
      --sample-config  prints a sample config file

Help Options:
  -h, --help           Show this help message
```
#### Exit Codes
```
0: no leaks
1: leaks present
2: error encountered
```

#### Additional Examples and Explanations
Check the wiki [here](https://github.com/zricethezav/gitleaks/wiki)

### If you find a valid leak in a repo
Please read this [Github article on removing sensitive data from a repository](https://help.github.com/articles/removing-sensitive-data-from-a-repository/) to remove the sensitive information from your history.

### Run me with docker
Simply run `docker run --rm --name=gitleaks zricethezav/gitleaks --help`
