
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

Gitleaks is a SAST tool for detecting hardcoded secrets like passwords, api keys, and tokens in git repos. Gitleaks is an **easy-to-use, all-in-one solution** for finding secrets, past or present, in your code.

### [Introduction Video](https://www.youtube.com/watch?v=VUq2eII20S4)


### Features:
- Scan for [commited](https://github.com/zricethezav/gitleaks#Scanning) secrets
- Scan for [unstaged](https://github.com/zricethezav/gitleaks#scan-unstaged-changes) secrets to shift security left
- Scan [directories and files](https://github.com/zricethezav/gitleaks#scan-local-directory)
- Run [Gitleaks Action](https://github.com/marketplace/actions/gitleaks) in your CI/CD pipeline
- [Custom rules](https://github.com/zricethezav/gitleaks#configuration) via toml configuration
- Increased performance using [go-git](https://github.com/go-git/go-git)
- json, sarif, and csv reporting
- Private repo scans using key or password based authentication


### Installation
Gitleaks can be installed using Homebrew, Docker, or Go. Gitleaks is also available in binary form for many popular platforms and OS types on the [releases page](https://github.com/zricethezav/gitleaks/releases). In addition, Gitleaks can be implemented as a pre-commit hook directly in your repo.

##### MacOS

```bash
brew install gitleaks
```

##### Docker

```bash
# To just pull the image
docker pull zricethezav/gitleaks:latest
# To run it from your cloned repo
cd to/your/repo/
docker run -v ${PWD}:/my-repo zricethezav/gitleaks:latest --path="/my-repo" [OPTIONS]
```

##### Go
```bash
GO111MODULE=on go get github.com/zricethezav/gitleaks/v7
```
##### As a pre-commit hook

See [pre-commit](https://github.com/pre-commit/pre-commit) for instructions.

Sample `.pre-commit-config.yaml`

```yaml
# The revision doesn't get updated manually
# check this https://github.com/zricethezav/gitleaks/releases
# to see if there are newer versions
-   repo: https://github.com/zricethezav/gitleaks
    rev: v7.6.0
    hooks:
    -   id: gitleaks
```

### Usage and Options
```
Usage:
  gitleaks [OPTIONS]

Application Options:
  -v, --verbose             Show verbose output from scan
  -q, --quiet               Sets log level to error and only output leaks, one json object per line
  -r, --repo-url=           Repository URL
  -p, --path=               Path to directory (repo if contains .git) or file
  -c, --config-path=        Path to config
      --repo-config-path=   Path to gitleaks config relative to repo root
      --clone-path=         Path to clone repo to disk
      --version             Version number
      --username=           Username for git repo
      --password=           Password for git repo
      --access-token=       Access token for git repo
      --threads=            Maximum number of threads gitleaks spawns
      --ssh-key=            Path to ssh key used for auth
      --unstaged            Run gitleaks on unstaged code
      --branch=             Branch to scan
      --redact              Redact secrets from log messages and leaks
      --debug               Log debug messages
      --no-git              Treat git repos as plain directories and scan those files
      --leaks-exit-code=    Exit code when leaks have been encountered (default: 1)
      --append-repo-config  Append the provided or default config with the repo config.
      --additional-config=  Path to an additional gitleaks config to append with an existing config. Can be used with --append-repo-config to append up to three configurations
  -o, --report=             Report output path
  -f, --format=             json, csv, sarif (default: json)
      --files-at-commit=    Sha of commit to scan all files at commit
      --commit=             Sha of commit to scan or "latest" to scan the last commit of the repository
      --commits=            Comma separated list of a commits to scan
      --commits-file=       Path to file of line separated list of commits to scan
      --commit-since=       Scan commits more recent than a specific date. Ex: '2006-01-02' or '2006-01-02T15:04:05-0700' format.
      --commit-until=       Scan commits older than a specific date. Ex: '2006-01-02' or '2006-01-02T15:04:05-0700' format.
      --depth=              Number of commits to scan

Help Options:
  -h, --help                Show this help message
```


### [Scanning](https://www.youtube.com/watch?v=WUzpRL8mKCk)

#### Basic repo-url scan:
This scans the entire history of tests/secrets and logs leaks as they are encountered `-v`/`--verbose` being set.
```bash
gitleaks --repo-url=https://github.com/my-insecure/repo -v
```


#### Basic repo-url scan output to a report:
If you want the report in sarif or csv you can set the `-f/--format` option
```bash
gitleaks --repo-url=https://github.com/my-insecure/repo -v --report=my-report.json
```

#### Scan specific commit:
```bash
gitleaks --repo-url=https://github.com/my-insecure/repo --commit=commit-sha -v
```

#### Scan local repo:
```bash
gitleaks --path=path/to/local/repo -v
```

#### Scan repos contained in a parent directory:
If you have `repo1`, `repo2`, `repo3` all under `path/to/local`, gitleaks will discover and scan those repos.
```bash
gitleaks --path=path/to/local/ -v
```

#### Scan local directory:
If you want to scan the current contents of a repo, ignoring git alltogether. You can use the `--no-git` option to do this.
```bash
gitleaks --path=path/to/local/repo -v --no-git
```

#### Scan a file:
Or if you want to scan a single file using gitleaks rules. You can do this by specifying the file in `--path` and including the `--no-git` option.
```bash
gitleaks --path=path/to/local/repo/main.go -v --no-git
```

#### Scan unstaged changes:
If you have unstaged changes are are currently at the root of the repo, you can run `gitleaks` with no `--path` or `--repo-url` specified which will run a scan on your uncommitted changes. Or if you want to specify a
path, you can run:
```bash
gitleaks --path=path/to/local/repo -v --unstaged
```


### Configuration
Provide your own gitleaks configurations with `--config-path` or `--repo-config-path`. `--config-path` loads a local gitleaks configuration whereas `--repo-config-path` will load a configuration present just in the repo you want to scan. For example, `gitleaks --repo-config-path=".github/gitleaks.config"`.
The default configuration Gitleaks uses is located [here](https://github.com/zricethezav/gitleaks/blob/master/config/gitleaks.toml). More configuration examples can be seen [here](https://github.com/zricethezav/gitleaks/tree/master/examples). Configuration files will contain a few different toml tables. Further explanation is provided below.

### Rules summary

The rules are written in [TOML](https://github.com/toml-lang/toml) as defined in [TomlLoader struct](https://github.com/zricethezav/gitleaks/blob/master/config/config.go#L57-L87), and can be summarized as:

```toml
[[rules]]
  description = "a string describing one of many rule in this config"
  regex = '''one-go-style-regex-for-this-rule'''
  file = '''a-file-name-regex'''
  path = '''a-file-path-regex'''
  tags = ["tag","another tag"]
  [[rules.entropies]] # note these are strings, not floats
    Min = "3.5"
    Max = "4.5"
    Group = "1"
  [rules.allowlist]
    description = "a string"
    files = ['''one-file-name-regex''']
    commits = [ "commit-A", "commit-B"]
    paths = ['''one-file-path-regex''']
    regexes = ['''one-regex-within-the-already-matched-regex''']

[allowlist]
  description = "a description string for a global allowlist config"
  commits = [ "commit-A", "commit-B"]
  files = [ '''file-regex-a''', '''file-regex-b''']
  paths = [ '''path-regex-a''', '''path-regex-b''']
  repos = [ '''repo-regex-a''', '''repo-regex-b''']
  regexes = ['''one-regex-within-the-already-matched-regex''']
```

Regular expressions are _NOT_ the full Perl set, so there are no look-aheads or look-behinds.


### Examples
#### Example 1
The first and most commonly edited array of tables is `[[rules]]`. This is where you can define your own custom rules for Gitleaks to use while scanning repos. Example keys/values within the `[[rules]]` table:
```toml
[[rules]]
  description = "generic secret regex"
  regex = '''secret(.{0,20})([0-9a-zA-Z-._{}$\/\+=]{20,120})'''
  tags = ["secret", "example"]
```
#### Example 2
We can also **combine** regular expressions AND entropy:
```toml
[[rules]]
  description = "entropy and regex example"
  regex = '''secret(.{0,20})['|"]([0-9a-zA-Z-._{}$\/\+=]{20,120})['|"]'''
  [[rules.Entropies]]
    Min = "4.5"
    Max = "4.7"
```
Translating this rule to English, this rule states: "if we encounter a line of code that matches *regex* AND the line falls within the bounds of a [Shannon entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)) of 4.5 to 4.7, then the line must be a leak"

#### Example 3
Let's compare two lines of code:
```
aws_secret='ABCDEF+c2L7yXeGvUyrPgYsDnWRRC1AYEXAMPLE'
```
and
```
aws_secret=os.getenv('AWS_SECRET_ACCESS_KEY')
```
The first line of code is an example of a hardcoded secret being assigned to the variable `aws_secret`. The second line of code is an example of a secret being assigned via env variables to `aws_secret`. Both would be caught by the rule defined in *example 2* but only the first line is actually a leak. Let's define a new rule that will capture only the first line of code. We can do this by combining regular expression **groups** and entropy.
```toml
[[rules]]
  description = "entropy and regex example"
  regex = '''secret(.{0,20})['|"]([0-9a-zA-Z-._{}$\/\+=]{20,120})['|"]'''
  [[rules.Entropies]]
    Min = "4.5"
    Max = "4.7"
    Group = "2"
```
Notice how we added `Group = "2"` to this rule. We can translate this rule to English: "if we encounter a line of code that matches regex AND the entropy of the *second regex group* falls within the bounds of a [Shannon entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)) of 4.5 to 4.7, then the line must be a leak"

### Example 4: Using allowlist regex

The proper Perl regex for AWS secret keys is
`(?<![A-Za-z0-9\\+])[A-Za-z0-9\\+=]{40}(?![A-Za-z0-9\\+=])`
but the Go library doesn't do lookahead/lookbehind, so
we'll look for 40 base64 characters, then allowlist
if they're embedded in a string of 41 base64 characters, that is,
without any delimiters. This will make a false negative for, say:
```
    foo=+awsSecretAccessKeyisBase64=40characters
```
So you can use the following to effectively create the proper Perl regex:
```toml
[[rules]]
  description = "AWS secret key regardless of labeling"
  regex = '''.?[A-Za-z0-9\\+=]{40}.?'''
  [rules.allowlist]
    description = "41 base64 characters is not an AWS secret key"
    regexes = ['''[A-Za-z0-9\\+=]{41}''']
```


### Exit Codes
You can always set the exit code when leaves are encountered with the `--leaks-exit-code` flag. Default exit codes below:
```
0 - no leaks present
1 - leaks or error encountered
```

###  Sponsors ❤️
#### Organization Sponsors
Sir, ehm, this is uhh... this is empty [😭](https://www.youtube.com/watch?v=w1o4O2SfQ5g)

#### Individual Sponsors
These users are [sponsors](https://github.com/sponsors/zricethezav) of gitleaks:

- [Adam Shannon](https://github.com/adamdecaf)
- [ProjectDiscovery](https://projectdiscovery.io/#/)
- [Ben "Ihavespoons"](https://github.com/ihavespoons)
- [Henry Sachs](https://github.com/henrysachs)

#### Logo Attribution
The Gitleaks logo uses the Git Logo created <a href="https://twitter.com/jasonlong">Jason Long</a> is licensed under the <a href="https://creativecommons.org/licenses/by/3.0/">Creative Commons Attribution 3.0 Unported License</a>.
