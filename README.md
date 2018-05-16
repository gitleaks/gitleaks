<p align="center">
  <img alt="gitleaks" src="https://raw.githubusercontent.com/zricethezav/gifs/master/gitleaks4.png" height="140" />
  <p align="center">
      <a href="https://travis-ci.org/zricethezav/gitleaks"><img alt="Travis" src="https://img.shields.io/travis/zricethezav/gitleaks/master.svg?style=flat-square"></a>
  </p>
</p>

## Audit git repos for secrets and keys

#### Installing

```bash
go get -u github.com/zricethezav/gitleaks
```
Or download from release binaries [here](https://github.com/zricethezav/gitleaks/releases)

#### Usage and Explanation

![Alt Text](https://github.com/zricethezav/gifs/blob/master/gitleaks.gif)

```bash
./gitleaks [options] <url/path>
```

Gitleaks audits local and remote repos by running regex checks against all commits.

#### Options
```
usage: gitleaks [options] <URL>/<path_to_repo>

Options:
 -u --user              Git user mode
 -r --repo              Git repo mode
 -o --org               Git organization mode
 -l --local             Local mode, gitleaks will look for local repo in <path>
 -t --temp              Clone to temporary directory
 -v --verbose           Verbose mode, will output leaks as gitleaks finds them
 --report-path=<STR>    Save report to path, gitleaks default behavior is to save report to pwd
 --clone-path=<STR>     Gitleaks will clone repos here, default pwd
 --concurrency=<INT>    Upper bound on concurrent diffs
 --regex-file=<STR>     Path to regex file for external regex matching
 --since=<STR>          Commit to stop at
 --b64Entropy=<INT>     Base64 entropy cutoff (default is 70)
 --hexEntropy=<INT>     Hex entropy cutoff (default is 40)
 -e --entropy           Enable entropy
 -h --help              Display this message
 --token=<STR>          Github API token
 --stopwords            Enables stopwords
```

#### Exit Codes 
code | explanation
 -------------|-------------
0 | Gitleaks succeeded with no leaks
1 | Gitleaks failed or wasn't attempted due to execution failure
2 | Gitleaks succeeded and leaks were present during the audit

Use these codes to hook gitleaks into whatever pipeline you're running

#### Examples
```bash
gitleaks
```
Run audit on current working directory if `.git` is present 

```bash
gitleaks --local $HOME/audits/some/repo
```
Run audit on repo located in `HOME/audits/some/repo` if `.git` is present 

```bash
gitleaks https://github.com/some/repo
```
Run audit on `github.com/some/repo.git` and clone repo to 

```bash
gitleaks --clone-path=$HOME/Desktop/audits https://github.com/some/repo
```
Run audit on `github.com/some/repo.git` and clone repo to $HOME/Desktop/audits 

```bash
gitleaks --temp https://github.com/some/repo
```
Run audit on `github.com/some/repo.git` and clone repo to $TMPDIR (this will remove repos after audit is complete)

```bash
gitleaks --temp -u https://github.com/some-user
```
Run audit on all of `some-user`'s repos. Again, `--temp` flag will clone all repos into $TMPDIR after be removed after audit 

```bash
gitleaks --regex-file=myregex.txt
```
Run audit on current working directory if `.git` is present and check for additional external regexes defined in `myregex.txt`. myregex.txt is just a text file containing a regular experession per line.
Sample external `regex-file`: 

```
[a-z0-9_-]{3,16}
[a-z]{3,16}
```




### If you find a valid leak in a repo
Please read the [Github article on removing sensitive data from a repository](https://help.github.com/articles/removing-sensitive-data-from-a-repository/) to remove the sensitive information from your history.

### Run me with docker

Simply run `docker run --rm --name=gitleaks zricethezav/gitleaks https://github.com/zricethezav/gitleaks`

Or build the image yourself to get the latest version :

```
docker build -t gitleaks .
docker run --rm --name=gitleaks gitleaks https://github.com/zricethezav/gitleaks
```

##### Consider using Gitleaks-CI
[Gitleaks-CI](https://github.com/zricethezav/gitleaks-ci) is 50 lines of bash code that checks your PRs for secrets you probably shouldn't be commiting

##### Support
BTC: 397zNMQnSUzGaqYw8XVa9YjNPiRpSZWkhX

ETH: 0x07eFa8c73235e18C9D7E7A1679751Aa9363CD99B

