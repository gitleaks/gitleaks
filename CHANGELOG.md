CHANGELOG
=========

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
- Default maximum goroutines spawned is number of cores your cpu run with. See benchmarks in wiki.
- Cleanup after each repo audit for organizations rather than waiting for the entire organization to complete. Eliminates risk of running out of disk space.


1.5.0
-----
- Support for CSV reporting
- Refactoring github user/owner audits

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
- Added support for providing an alternate GitHub URL to support scanning GitHub Enteprise repositories

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

