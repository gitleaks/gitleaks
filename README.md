<p align="center">
  <img alt="gitleaks" src="https://raw.githubusercontent.com/zricethezav/gifs/master/gitleakslogo.png" height="70" />
  <p align="center">
      <a href="https://travis-ci.org/zricethezav/gitleaks"><img alt="Travis" src="https://img.shields.io/travis/zricethezav/gitleaks/master.svg?style=flat-square"></a>
  </p>
</p>

Gitleaks is a SAST tool for detecting hardcoded secrets like passwords, api keys, and tokens in git repos. Gitleaks aims to be the **easy-to-use, all-in-one solution** for finding secrets, past or present, in your code. 
 
### Features:
- Scan for [commited](https://github.com/zricethezav/gitleaks#Scanning) secrets
- Scan for [unstaged](https://github.com/zricethezav/gitleaks#scan-unstaged-changes) secrets as part of shifting security left
- Scan [directories and files](https://github.com/zricethezav/gitleaks#scan-local-directory)
- Available [Github Action](https://github.com/marketplace/actions/gitleaks)
- [Custom rules](https://github.com/zricethezav/gitleaks#configuration) via toml configuration
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


### [Scanning](https://www.youtube.com/watch?v=WUzpRL8mKCk)

#### Basic repo-url scan:
This scans the entire history of tests/secrets and logs leaks as they are encountered `-v`/`--verbose` being set.
```
gitleaks --repo-url=https://github.com/my-insecure/repo -v
```


#### Basic repo-url scan output to a report:
If we want the report in sarif or csv we can set the `-f/--format` option
```
gitleaks --repo-url=https://github.com/my-insecure/repo -v --report=my-report.json
```

#### Scan specific commit:
```
gitleaks --repo-url=https://github.com/my-insecure/repo --commit=commit-sha -v
```

#### Scan local repo:
```
gitleaks --path=path/to/local/repo -v
```

#### Scan repos contain in a parent directory:
If we had `repo1`, `repo2`, `repo3` all under `path/to/local`, gitleaks will discover and scan those repos.
```
gitleaks --path=path/to/local/ -v
```

#### Scan local directory:
You might want to scan the current contents of a repo, ignoring git alltogether. You can use the `--no-git` option to do this.
```
gitleaks --path=path/to/local/repo -v --no-git
```

#### Scan a file:
Or you might want to scan a single file using gitleaks rules. You can do this by specifying the file in `--path` and including the `--no-git` option.
```
gitleaks --path=path/to/local/repo/main.go -v --no-git
```

#### Scan unstaged changes:
If you have unstaged changes are are currently at the root of the repo, you can run `gitleaks` with no `--path` or `--repo-url` specified which will run a scan on your uncommitted changes. Or if you want to specify a 
path, you can run:
```
gitleaks --path=path/to/local/repo -v --unstaged
```


### Configuration
Provide your own gitleaks configurations with `--config-path` or `--repo-config-path`. The difference between the two is `--config-path` loads a local gitleaks config whereas `--repo-config-path` will load a configuration present in the repo you want to scan. For example, `gitleaks --repo-config-path=".github/gitleaks.config"`.
The default configuration Gitleaks uses is located [here](https://github.com/zricethezav/gitleaks/blob/master/config/default.go). More configuration examples can be seen [here](https://github.com/zricethezav/gitleaks/tree/master/examples). Configuration files contain a few different toml tables which will be explained below.
### Rules summary

The rules are written in [TOML](https://github.com/toml-lang/toml) as defined in [TomlLoader struct](https://github.com/zricethezav/gitleaks/blob/master/config/config.go#L57-L87), and can be summarized as:

```


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
```
[[rules]]
  description = "generic secret regex"
  regex = '''secret(.{0,20})([0-9a-zA-Z-._{}$\/\+=]{20,120})'''
  tags = ["secret", "example"]
```
#### Example 2
We can also **combine** regular expressions AND entropy:
```
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
```
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
```
[[rules]]
	description = "AWS secret key regardless of labeling"
	regex = '''.?[A-Za-z0-9\\+=]{40}.?'''
	[rules.allowlist]
                description = "41 base64 characters is not an AWS secret key"
		regexes = ['''[A-Za-z0-9\\+=]{41}''']
		
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

