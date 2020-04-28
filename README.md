<p align="center">
  <img alt="gitleaks" src="https://raw.githubusercontent.com/zricethezav/gifs/master/gitleakslogo.png" height="70" />
  <p align="center">
      <a href="https://travis-ci.org/zricethezav/gitleaks"><img alt="Travis" src="https://img.shields.io/travis/zricethezav/gitleaks/master.svg?style=flat-square"></a>
  </p>
</p>

Gitleaks is a SAST tool for detecting hardcoded secrets like passwords, api keys, and tokens in git repos. 




|  `repo scan` |
|---|
| <p align="left"><img src="https://raw.githubusercontent.com/zricethezav/gifs/master/repo-scan.gif"></p>  | <p align="left"><img src="https://raw.githubusercontent.com/zricethezav/gifs/master/repo-scan.gif"></p> |

| `pre commit scan` |
|---|
|  <p align="left"><img src="https://raw.githubusercontent.com/zricethezav/gifs/master/pre-commit-1.gif"></p> |

## Getting Started

Written in Go, gitleaks is available in binary form for many popular platforms and OS types from the [releases page](https://github.com/zricethezav/gitleaks/releases). Alternatively, executed via Docker or it can be installed using Go directly, as per the below;

#### MacOS

```
brew install gitleaks
```

#### Docker

```bash
docker pull zricethezav/gitleaks
```

#### Go
```bash
go get github.com/zricethezav/gitleaks/v4
```

## Usage

Gitleaks has a wide range of configuration options that can be adjusted at runtime or via a configuration file based on your specific requirements.

```
Usage:
  gitleaks [OPTIONS]

Application Options:
  -v, --verbose          Show verbose output from audit
  -r, --repo=            Target repository
      --config=          config path
     ...

Help Options:
  -h, --help             Show this help message
```
## Configuration 
Gitleaks provides the abilitiy to define your own rules for scanning secrets. Combine the power of regex, entropy, and regex group targeting for a finely tuned scan. Below is an example rule combining all three for an effective generic secret rule. Please view the documentation page for additional examples.


### Docker usage examples

Run gitleaks against:

###### Public repository

```bash
docker run --rm --name=gitleaks zricethezav/gitleaks -v -r https://github.com/zricethezav/gitleaks.git
```

###### Local repository already cloned into /tmp/

```bash
docker run --rm --name=gitleaks -v /tmp/:/code/ zricethezav/gitleaks -v --repo-path=/code/gitleaks
```

By default repos cloned to memory. Using `--disk` for clone to disk or you can quickly out of memory.

For speed up analyze operation using `--threads` parameter, which set to `ALL - 1` threads at your instance CPU.


## Exit Codes

Gitleaks provides consistent exist codes to assist in automation workflows such as CICD platforms and bulk scanning.


```
0: no leaks
1: leaks present
2: error encountered
```
----

###  Sponsors ❤️
These users are [sponsors](https://github.com/sponsors/zricethezav) of gitleaks:

[![Adam Shannon](https://github.com/adamdecaf.png?size=50)](https://github.com/adamdecaf) | [![Granville Schmidt](https://github.com/gramidt.png?size=50)](https://github.com/gramidt) | 
---|---|
----
#### Logo Attribution
The Gitleaks logo uses the Git Logo created <a href="https://twitter.com/jasonlong">Jason Long</a> is licensed under the <a href="https://creativecommons.org/licenses/by/3.0/">Creative Commons Attribution 3.0 Unported License</a>.

