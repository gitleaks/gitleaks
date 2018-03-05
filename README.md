![Alt Text](https://github.com/zricethezav/gifs/blob/master/gitleaks1.png) [![Build Status](https://travis-ci.org/zricethezav/gitleaks.svg?branch=master)](https://travis-ci.org/zricethezav/gitleaks)
## Audit git repos for secrets and keys

#### Installing

```bash
go get -u github.com/zricethezav/gitleaks
```

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
 --since=<STR>          Commit to stop at
 --b64Entropy=<INT>     Base64 entropy cutoff (default is 70)
 --hexEntropy=<INT>     Hex entropy cutoff (default is 40)
 -e --entropy           Enable entropy
 -h --help              Display this message
 --token=<STR>          Github API token
 --stopwords            Enables stopwords
```

#### Exit Codes 
Use these codes to hook gitleaks into whatever pipeline you're running
| code | explanation |
| ------------- | ------------- |
| 0 | Gitleaks succeeded with no leaks |
| 1 | Gitleaks failed or wasn't attempted due to execution failure |
| 2 | Gitleaks succeeded and leaks were present during the audit |

#### Examples
```bash
gitleaks
```
Run audit on current working directory if `.git` is present |

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




### If you find a valid leak in a repo
Please read the [Github article on removing sensitive data from a repository](https://help.github.com/articles/removing-sensitive-data-from-a-repository/) to remove the sensitive information from your history.

### Run me with docker

Simply run `docker run --rm --name=gitleaks zricethezav/gitleaks https://github.com/zricethezav/gitleaks`

Or build the image yourself to get the latest version :

```
docker build -t gitleaks .
docker run --rm --name=gitleaks gitleaks https://github.com/zricethezav/gitleaks
```

### cypherphunky
BTC: 1H2rSXDJZxWcTk2Ugr5P9r9m93m2NhL4xj

BCH: qp4mdaef04g5d0xpgecx78fmruk6vgl4pgqtetrl9h

ETH: 0xe48b4Fce6A1C1a9C780376032895b06b1709AddF

LTC: LRhDzMyGos5CtZMoSTEx5rdLksPUwSrtuz

s/o to @jlakowski for the gimp skillz
