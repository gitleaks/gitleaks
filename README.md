<p align="center">
  <img alt="gitleaks" src="https://raw.githubusercontent.com/zricethezav/gifs/master/gitleaks5.png" height="140" />
  <p align="center">
      <a href="https://travis-ci.org/zricethezav/gitleaks"><img alt="Travis" src="https://img.shields.io/travis/zricethezav/gitleaks/master.svg?style=flat-square"></a>
  </p>
</p>

## Audit git repos for secrets

Gitleaks provides a way for you to find unencrypted secrets and other unwanted data types in git source code repositories.

As part of it's core functionality, it provides;
* Github support including support for bulk organisation and repository owner (user) repository scans, as well as pull request scanning for use in common CI workflows.
* Support for private repository scans, and repositories that require key based authentication
* Output in CSV and JSON formats for consumption in other reporting tools and frameworks
* Externalised configuration for environment specific customisation including regex rules
* Customisable repository name, file type, commit ID, branchname and regex whitelisting to reduce false positives
* High performance through the use of src-d's [go-git](https://github.com/src-d/go-git) framework


It has been sucessfully used in a number of different scenarios, including;
* Adhoc scans of local and remote repositories by filesystem path or clone URL
* Automated scans of github users and organisations (Both public and enterprise platforms)
* As part of a CICD workflow to identify secrets before they make it deeper into your codebase
* As part of a wider secrets auditing automation capability for git data in large environments


### Example execution


<p align="left">
    <img src="https://cdn.rawgit.com/zricethezav/5bf8259b7fea0170becffc06b8588edb/raw/f762769fe20ef3669bff34612b1bede6457631e6/termtosvg_je8bp82s.svg">
</p>

#### Installation
Written in Go, gitleaks is available in binary form for many popular platforms and OS types from the [releases page](https://github.com/zricethezav/gitleaks/releases). Alternatively, executed via Docker or it can be installed using Go directly, as per the below;

##### Docker

```bash
# Run gitleaks against a public repository
docker run --rm --name=gitleaks zricethezav/gitleaks -v -r  https://github.com/zricethezav/gitleaks.git

# Run gitleaks against a local repository already cloned into /tmp/
docker run --rm --name=gitleaks -v /tmp/:/code/  zricethezav/gitleaks -v --repo-path=/code/gitleaks

# Run gitleaks against a specific Github Pull request
docker run --rm --name=gitleaks -e GITHUB_TOKEN={your token} zricethezav/gitleaks --github-pr=https://github.com/owner/repo/pull/9000
```

##### Go

```bash
go get -u github.com/zricethezav/gitleaks
```

#### Usage and Options
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
  -c, --commit=         sha of commit to stop at
      --depth=          maximum commit depth
      --repo-path=      Path to repo
      --owner-path=     Path to owner directory (repos discovered)
      --threads=        Maximum number of threads gitleaks spawns
      --disk            Clones repo(s) to disk
      --single-search=  single regular expression to search for
      --config=         path to gitleaks config
      --ssh-key=        path to ssh key
      --exclude-forks   exclude forks for organization/user audits
  -e, --entropy=        Include entropy checks during audit. Entropy scale: 0.0(no entropy) - 8.0(max entropy)
      --noise-reduction Reduce the number of finds when entropy checks are enabled
      --repo-config     Load config from target repo. Config file must be ".gitleaks.toml"
  -l, --log=            log level
  -v, --verbose         Show verbose output from gitleaks audit
      --report=         path to write report file
      --redact          redact secrets from log messages and report
      --version         version number
      --sample-config   prints a sample config file

Help Options:
  -h, --help           Show this help message
```

#### Exit Codes
Gitleaks provides consistent exist codes to assist in automation workflows such as CICD platforms and bulk scanning.

These can be effectively used in conjunction with the report output file to detect and return meaningful data back to the user or external system about if leaks have been detected, and where they reside.

The code return codes are:

```
0: no leaks
1: leaks present
2: error encountered
```

### Additional information
* Additional documentation about how gitleaks functions can be found on the [wiki page](https://github.com/zricethezav/gitleaks/wiki)
* The below links detail the various approaches to remediating unwanted data in git repos
    * [Removing sensitive data from a repository (github.com)](https://help.github.com/articles/removing-sensitive-data-from-a-repository/)
    * [Removing sensitive files from commit history (atlassian.com)](https://community.atlassian.com/t5/Bitbucket-questions/Remove-sensitive-files-from-commit-history/qaq-p/243807)
    * [Rewrite git history with the BFG (theguardian.com)](https://www.theguardian.com/info/developer-blog/2013/apr/29/rewrite-git-history-with-the-bfg)
* [Auditing Bitbucket Server Data for Credentials in AWS (sourcedgroup.com)](https://www.sourcedgroup.com/blog/auditing-bitbucket-server-data-credentials-in-aws)

    This blog post details how gitleaks was used to audit data in Atlassian Bitbucket server when hosted on AWS and visualise the results in a compliance dashboard using Splunk.

* How does gitleaks differ to Github token scanning?
    * [Github recently announced](https://blog.github.com/2018-10-16-future-of-software/#github-token-scanning-for-public-repositories-public-beta) a new capability to their cloud platform that detects exposed credentials for a number of common services and platforms and automatically notifies the provider for revocation or similar action. Gitleaks provides a similar detection capability for non-Github cloud users, in which repositories can be easily audited and results provided in a number of formats.

### Give Thanks
If using gitleaks has made you job easier consider donating to an organization, C-U at Home, that does vital work for those who most need it in the community of Champaign-Urbana, IL (my home).

From C-U at Home:

```C-U at Home is a grassroots, 501 c (3), faith-based homelessness ministry with facilities located in the Champaign-Urbana area. Due to our not-for-profit status, all gifts made to C-U at Home (both monetary and in-kind) are tax deductible. Our ministry is funded 100% by the community and we have made it a priority not to accept any state or federal funds. We feel that through community dollars, we can stay true to our mission. While our mission statement reads, “C-U at Home engages and mobilizes our community to house and support the most vulnerable homeless on their journey of healing and restoration,” our connection with those we serve goes much deeper.```

<b>Donate</b>: https://www.cuathome.us/give/

#### Speaking of Community
Please read this https://corruptcu.com/



