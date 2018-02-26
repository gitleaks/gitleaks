![Alt Text](https://github.com/zricethezav/gifs/blob/master/gitleaks1.png) [![Build Status](https://travis-ci.org/zricethezav/gitleaks.svg?branch=master)](https://travis-ci.org/zricethezav/gitleaks)
## Check git repos for secrets and keys

#### Installing

```bash
go get -u github.com/zricethezav/gitleaks
```

#### Usage and Explanation

![Alt Text](https://github.com/zricethezav/gifs/blob/master/gitleaks.gif)

```bash
./gitleaks {git url}
```

Gitleaks will clone the target `<git url>` to `$HOME/.gitleaks/clones/<repo name>` and run a regex check against all diffs of all commits on all remotes in topological order. If any leaks are found gitleaks will output the leak in json, Ex:
```
{
   "line": "-const AWS_KEY = \"AKIALALEMEL33243OLIAE\"",
   "commit": "eaeffdc65b4c73ccb67e75d96bd8743be2c85973",
   "string": "AKIALALEMEL33243OLIA",
   "reason": "AWS",
   "commitMsg": "remove fake key",
   "time": "2018-02-04 19:43:28 -0600",
   "author": "Zachary Rice",
   "file": "main.go",
   "repoURL": "https://github.com/zricethezav/gronit"
}
``` 
Gitleaks will not re-clone repos unless the temporary flag is set (see Options section), instead gitleaks will `fetch` all new changes before the scan. This works for users and organization repos as well. Regex's for the scan are defined in `main.go`, feel free to open a PR and contribute if you have additional regex you want included. Work largely based on  [https://people.eecs.berkeley.edu/~rohanpadhye/files/key_leaks-msr15.pdf](https://people.eecs.berkeley.edu/~rohanpadhye/files/key_leaks-msr15.pdf) and regexes from https://github.com/dxa4481/truffleHog and https://github.com/anshumanbh/git-all-secrets.

#### Example with Report
```bash
gitleaks --json https://github.com/zricethezav/gronit
```
This will run gitleaks on one of my projects, gronit and create the following structure in `$HOME/.gitleaks`:
```
.
├── clones
│   └── zricethezav
│       └── gronit
│           ├── README.md
│           ├── main.go
│           ├── options.go
│           ├── server.go
│           └── utils.go
└── report
    └── zricethezav
        └── gronit_leaks.json
```
The clones directory contains the repo owner (me) and any repos gitleaks has scanned. Next time we run gitleaks on gronit again we will `fetch` gronit rather than `clone`. Reports are written out to `$HOME/.gitleaks/report/<owner>/<repo>_leaks.json`

#### Options
```
usage: gitleaks [options] <url>

Options:
 -c --concurrency 	Upper bound on concurrent diffs
 -u --user 		    Git user url
 -r --repo 		    Git repo url
 -o --org 		    Git organization url
 -s --since 		Commit to stop at
 -b --b64Entropy 	Base64 entropy cutoff (default is 70)
 -x --hexEntropy  	Hex entropy cutoff (default is 40)
 -e --entropy		Enable entropy		
 -j --json 		    Output gitleaks report
 --token    		Github API token
 --strict 		    Enables stopwords
 -h --help 		    Display this message

```

##### Options Explained

| Option | Explanation |
| ------------- | ------------- |
| -c --concurrency | Set the limit on the number of concurrent diffs. If unbounded, your system would throw a `too many open files` error. Tweak `ulimit` for quicker scans at your own risk. Ex: `gitleaks -c 100 <repo_url>` |
| -u --user | Target git user. Reports and clones are dumped to `$HOME/.gitleaks/clones/<user>/<user_repos>` and `$HOME/.gitleaks/reports/<user>/<gitleaks_reports>`. Ex: `gitleaks -u <user_git_url>`.
| -o --org | Target git organization. Reports and clones are dumped to `$HOME/.gitleaks/clones/<org>/<org_repos>` and `$HOME/.gitleaks/reports/<org>/<gitleaks_reports>`. Ex: `gitleaks -o <org_git_url>`
| -r --repo | Default behavior is to have gitleaks target a specific repo, so this option is unecessary, but... Target git repo. Reports and clones are dumped to `$HOME/.gitleaks/clones/<owner>/<repos>` and `$HOME/.gitleaks/reports/<owner>/<gitleaks_reports>`
| -s --since  | Since argument accepts a commit hash and will scan the repo history up to and including this hash. Ex: `gitleaks -s <HASH> <repo_url>`
| -b --b64Entropy | Entropy cutoff for base 64 characters. Ex: `gitleaks -e -b 70 <repo_url>` |
| -x --hexEntropy | Entropy cutoff for hex characters. Ex: `gitleaks -e -x 70 <repo_url>` |
| -e --entroy | Enable entropy checks. Ex: `gitleaks -e <repo_url>` |
| -j --json | Enable report generation. Ex: `gitleaks --json <repo_url>` | 
| -t --temporary | Cloned repos will be cloned into a temp directory and removed after gitleaks exits. Ex: `gitleaks -t <repo_url>` |
| --token | NOTE: you should use env var `GITHUB_TOKEN` instead of this flag. Github API token needed for scanning private repos and pagination on repo fetching from github's api. |
| -- strict | Enable stopwords. Ex: `gitleaks --strict <repo_url>` |

NOTE: your mileage may vary so if you aren't getting the results you expected try updating the regexes to fit your needs or try tweaking the entropy cutoffs and stopwords. Entropy cutoff for base64 alphabets seemed to give good results around 70 and hex alphabets seemed to give good results around 40. Entropy is calculated using [Shannon entropy](http://www.bearcave.com/misl/misl_tech/wavelets/compression/shannon.html).


### If you find a valid leak in a repo
Please read the [Github article on removing sensitive data from a repository](https://help.github.com/articles/removing-sensitive-data-from-a-repository/) to remove the sensitive information from your history.

### Run me with docker

Simply run `docker run --rm --name=gitleaks raphaelareya/gitleaks https://github.com/zricethezav/gitleaks`

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
