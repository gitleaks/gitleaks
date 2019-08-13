Gitleaks
--------

<p align="left">
      <a href="https://travis-ci.org/zricethezav/gitleaks"><img alt="Travis" src="https://img.shields.io/travis/zricethezav/gitleaks/master.svg?style=flat-square"></a>
</p>

Audit git repos for secrets. Gitleaks provides a way for you to find unencrypted secrets and other unwanted data types in git source code repositories. As part of it's core functionality, it provides:

* Github and Gitlab support including support for bulk organization and repository owner (user) repository scans, as well as pull request scanning for use in common CI workflows.
* Support for private repository scans, and repositories that require key based authentication
* Output in CSV and JSON formats for consumption in other reporting tools and frameworks
* Externalised configuration for environment specific customisation including regex rules
* Customizable repository name, file type, commit ID, branch name and regex whitelisting to reduce false positives
* High performance through the use of src-d's [go-git](https://github.com/src-d/go-git) framework

It has been successfully used in a number of different scenarios, including:

* Adhoc scans of local and remote repositories by filesystem path or clone URL
* Automated scans of github users and organizations (Both public and enterprise platforms)
* As part of a CICD workflow to identify secrets before they make it deeper into your codebase
* As part of a wider secrets auditing automation capability for git data in large environments


## Example execution


<p align="left">
    <img src="https://cdn.rawgit.com/zricethezav/5bf8259b7fea0170becffc06b8588edb/raw/f762769fe20ef3669bff34612b1bede6457631e6/termtosvg_je8bp82s.svg">
</p>

## Installation

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
go get -u github.com/zricethezav/gitleaks
```

## Usage and Options

gitleaks has a wide range of configuration options that can be adjusted at runtime or via a configuration file based on your specific requirements.

```
Usage:
  gitleaks [OPTIONS]

Application Options:
  -r, --repo=           Repo url to audit
      --github-user=    Github user to audit
      --github-org=     Github organization to audit
      --github-url=     GitHub API Base URL, use for GitHub Enterprise. Example: https://github.example.com/api/v3/ (default: https://api.github.com/)
      --github-pr=      Github PR url to audit. This does not clone the repo. GITHUB_TOKEN must be set
      --gitlab-user=    GitLab user ID to audit
      --gitlab-org=     GitLab group ID to audit
      --commit-stop=    sha of commit to stop at
      --commit=         sha of commit to audit
      --depth=          maximum commit depth
      --repo-path=      Path to repo
      --owner-path=     Path to owner directory (repos discovered)
      --threads=        Maximum number of threads gitleaks spawns
      --disk            Clones repo(s) to disk
      --config=         path to gitleaks config
      --ssh-key=        path to ssh key
      --exclude-forks   exclude forks for organization/user audits
      --repo-config     Load config from target repo. Config file must be ".gitleaks.toml"
      --branch=         Branch to audit
  -l, --log=            log level
  -v, --verbose         Show verbose output from gitleaks audit
      --report=         path to write report file
      --redact          redact secrets from log messages and report
      --version         version number
      --sample-config   prints a sample config file

Help Options:
  -h, --help           Show this help message
```

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

###### Specific Github Pull request

You need GitHub token with `repo` access. [How create token](https://help.github.com/en/articles/creating-a-personal-access-token-for-the-command-line).

```bash
  export GITHUB_TOKEN=""

docker run --rm --name=gitleaks \
    -e GITHUB_TOKEN=${GITHUB_TOKEN} \
    zricethezav/gitleaks \
        --github-pr=https://github.com/owner/repo/pull/9000
```

###### Private repository

You need private SSH key associated with user which have pull access to private repo.

```bash
export SSH_KEY_DIR=$(echo $HOME)/.ssh
export SSH_KEY_NAME=id_rsa
export REPO="git@github.com:zricethezav/gitleaks.git"

docker run --rm --name=gitleaks \
    --mount type=bind,src=${SSH_KEY_DIR},dst=/root/.ssh,readonly \
    zricethezav/gitleaks \
        --ssh-key=/root/.ssh/${SSH_KEY_NAME} \
        --verbose \
        --repo=${REPO}
```

###### Specific Github organization with private repos

You need GitHub token with `repo` access. [How create token](https://help.github.com/en/articles/creating-a-personal-access-token-for-the-command-line).

```bash
  export GITHUB_TOKEN=""
export ORG="github_org_name" # "git" in "https://github.com/git/", for instance.

docker run --rm --name=gitleaks \
    -e GITHUB_TOKEN=${GITHUB_TOKEN} \
    zricethezav/gitleaks \
        --verbose \
        --disk \
        --threads=$(($(nproc --all) - 1)) \
        --github-org=${ORG}
```

By default repos cloned to memory. Using `--disk` for clone to disk or you can quickly out of memory.

For speed up analyze operation using `--threads` parameter, which set to `ALL - 1` treads at your instance CPU.


## Exit Codes

Gitleaks provides consistent exist codes to assist in automation workflows such as CICD platforms and bulk scanning.

These can be effectively used in conjunction with the report output file to detect and return meaningful data back to the user or external system about if leaks have been detected, and where they reside.

The code return codes are:

```
0: no leaks
1: leaks present
2: error encountered
```

## Additional information

* Additional documentation about how gitleaks functions can be found on the [wiki page](https://github.com/zricethezav/gitleaks/wiki)
* The below links detail the various approaches to remediating unwanted data in git repos
    * [Removing sensitive data from a repository (github.com)](https://help.github.com/articles/removing-sensitive-data-from-a-repository/)
    * [Removing sensitive files from commit history (atlassian.com)](https://community.atlassian.com/t5/Bitbucket-questions/Remove-sensitive-files-from-commit-history/qaq-p/243807)
    * [Rewrite git history with the BFG (theguardian.com)](https://www.theguardian.com/info/developer-blog/2013/apr/29/rewrite-git-history-with-the-bfg)
* [Auditing Bitbucket Server Data for Credentials in AWS (sourcedgroup.com)](https://www.sourcedgroup.com/blog/auditing-bitbucket-server-data-credentials-in-aws)

    This blog post details how gitleaks was used to audit data in Atlassian Bitbucket server when hosted on AWS and visualise the results in a compliance dashboard using Splunk.

* How does gitleaks differ to Github token scanning?
    * [Github recently announced](https://blog.github.com/2018-10-16-future-of-software/#github-token-scanning-for-public-repositories-public-beta) a new capability to their cloud platform that detects exposed credentials for a number of common services and platforms and automatically notifies the provider for revocation or similar action. Gitleaks provides a similar detection capability for non-Github cloud users, in which repositories can be easily audited and results provided in a number of formats.

## Give Thanks

If using gitleaks has made you job easier consider donating to one of [Sam](https://www.flickr.com/photos/146541520@N08/albums/72157710121716312)'s favorite places, the Japan House on the University of Illinois at Urbana-Champaign's campus: https://japanhouse.illinois.edu/make-a-gift

