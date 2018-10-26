CHANGELOG
=========

1.17.0
----
- Default regex added to search: slack, telegram.
- Default whitelisting: bin, doc, jpeg, gif

1.16.1
----
- Fixing default ssh auth logic

1.16.0
----
- Better commit coverage. Now iterates through each commit in git log and generates a patch with each commit's parent.
- Removing the need for --private/-p option. Instead gitleaks will determine if the repo is private or not.


1.15.0
----
- Whitelist repos use regex now
- Whitelist repo check before clone

1.14.0
----
- Entropy Range support in gitleaks config

1.13.0
----
- Github PR support
- Github has its own go file. All other services, bitbucket, gitlab, etc should follow this convention

1.12.1
----
- Show program usage when no arguments are provided
- Exit program after the -h or --help options are used

1.12.0
----
- removing --csv option
- --report option now requires .json or .csv in filename
- adding total time to audit in logs

1.11.1
----
- fix commit whitelist logic

1.11.0
-----
- Commit depth option
- Commit stats output

1.10.0
-----
- Add entropy option

1.9.0
-----
- exclude fork option

1.8.0
-----
- whitelist repos
- sample config option

1.7.3
-----
- style points

1.7.2
-----
- Fixing dangling goroutines, removing channel messaging

1.7.1
-----
- Fixing bug where single repos were not being audited

1.7.0
-----
- Exit code == 2 on error
- Cleaning up some logs
- Removing some unreachable code

1.6.1
-----
- Recover from panic when diffing

1.6.0
-----
- Default maximum goroutines spawned is number of cores your CPU run with. See benchmarks in wiki.
- Cleanup after each repo audit for organizations rather than waiting for the entire organization to complete. Eliminates the risk of running out of disk space.


1.5.0
-----
- Support for CSV reporting
- Refactoring Github user/owner audits

1.4.0
-----
- Support for single commit repos
- Bumped go-git version from 4.5.0 to 4.7.0

1.3.0
-----
- Target specific branch

1.2.1
-----
- Check errors when generating commit patch

1.2.0
-----
- Added support for providing an alternate GitHub URL to support scanning GitHub Enterprise repositories

1.1.2
-----
- Added version option
- Introduced changelog

1.1.1
-----
- Fixed commit patch order
- Updated Readme

1.1.0
-----
- Fixed Twitter typo
- Fixed sample docker command
- Default clone option to "in-memory"
- Added clone option for "disk"
- Updated Makefile

1.0.0
-----
- Rewrite, see Readme.md: https://github.com/zricethezav/gitleaks/releases/tag/v1.0.0

0.4.0
-----
- Added support for external regexes

0.3.0
-----
- Added local scan
- Meaningful exit codes
- Timestamped logs
- Refactored for some maintainability

0.2.0
-----
- Additionally regex checking
- $HOME/.gitleaks/ directory for clones and reports
- Pagination for Org/User list... no more partial repo lists
- Persistent repos for Orgs and Users (no more re-cloning)
- Updated README
- Multi-staged Docker build
- Travis CI

0.1.0
-----
- full git history search
- regex/entropy checks
- report generation

