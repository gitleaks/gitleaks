<p align="center">
  <img alt="gitleaks" src="https://raw.githubusercontent.com/zricethezav/gifs/master/gitleaks5.png" height="140" />
  <p align="center">
      <a href="https://travis-ci.org/zricethezav/gitleaks"><img alt="Travis" src="https://img.shields.io/travis/zricethezav/gitleaks/master.svg?style=flat-square"></a>
  </p>
</p>

## Audit git repos for secrets, keys, and whatever.
### Powered by src-d's [go-git](https://github.com/src-d/go-git)

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
      --github-user=   User url to audit
      --github-org=    Organization url to audit
  -p, --private        Include private repos in audit
  -c, --commit=        sha of commit to stop at
      --repo-path=     Path to repo
      --owner-path=    Path to owner directory (repos discovered)
      --max-go=        Maximum number of concurrent go-routines gitleaks spawns
  -m, --in-memory      Run gitleaks in memory
      --all-refs       run audit on all refs
      --single-search= single regular expression to search for
      --config=        path to gitleaks config
      --ssh-key=       path to ssh key
  -l, --log=           log level
  -v, --verbose        Show verbose output from gitleaks audit
      --report=        path to write report file
      --redact         redact secrets from log messages and report

Help Options:
  -h, --help           Show this help message
```
#### Exit Codes
```
1: leaks present
0: no leaks
```

#### Additional Examples and Explanations
Check the wiki [here](https://github.com/zricethezav/gitleaks/wiki)

### If you find a valid leak in a repo
Please read this [Github article on removing sensitive data from a repository](https://help.github.com/articles/removing-sensitive-data-from-a-repository/) to remove the sensitive information from your history.

### Run me with docker
Simply run `docker run --rm --name=gitleaks zricethezav/gitleaks https://github.com/zricethezav/gitleaks`