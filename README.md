<p align="center">
  <img alt="gitleaks" src="https://raw.githubusercontent.com/zricethezav/gifs/master/gitleaks5.png" height="140" />
  <p align="center">
      <a href="https://travis-ci.org/zricethezav/gitleaks"><img alt="Travis" src="https://img.shields.io/travis/zricethezav/gitleaks/master.svg?style=flat-square"></a>
  </p>
</p>

## Audit git repos for secrets, keys, and whatever

#### Installing

```bash
go get -u github.com/zricethezav/gitleaks
```
Or download from release binaries [here](https://github.com/zricethezav/gitleaks/releases)

#### Usage and Explanation

```bash
./gitleaks [Options]
```

Gitleaks audits local and remote repos by running regex checks against all commits against origin/HEAD or optionally against all git references.

#### Options
```
Usage:
  gitleaks [OPTIONS]

Application Options:
  -r, --repo=          Repo url to audit
      --github-user=   User url to audit
      --github-org=    Organization url to audit
      --private        Include private repos in audit
  -b, --branch=        branch name to audit (defaults to HEAD)
      --commit=        sha of commit to stop at
      --repo-path=     Path to repo
      --owner-path=    Path to owner directory (repos discovered)
      --max-go=        Maximum number of concurrent go-routines gitleaks spawns
      --in-memory      Run gitleaks in memory
      --branches-all   run audit on all branches
      --single-search= single regular expression to search for
      --config=        path to gitleaks config
      --ssh-key=       path to ssh key
      --messages=      include commit messages in audit
      --log-level=     log level
  -v, --verbose        Show verbose output from gitleaks audit
      --report=        path to report
      --redact=        redact secrets from log messages and report

Help Options:
  -h, --help           Show this help message

```

#### Examples



### If you find a valid leak in a repo
Please read the [Github article on removing sensitive data from a repository](https://help.github.com/articles/removing-sensitive-data-from-a-repository/) to remove the sensitive information from your history.

### Run me with docker

Simply run `docker run --rm --name=gitleaks zricethezav/gitleaks https://github.com/zricethezav/gitleaks`


##### Consider using Gitleaks-CI
[Gitleaks-CI](https://github.com/zricethezav/gitleaks-ci) is 50 lines of bash code that checks your PRs for secrets you probably shouldn't be commiting

##### Support
BTC: 397zNMQnSUzGaqYw8XVa9YjNPiRpSZWkhX

ETH: 0x07eFa8c73235e18C9D7E7A1679751Aa9363CD99B

