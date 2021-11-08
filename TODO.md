### TODO list
- [x] ViperConfig -> Config conversion
- [x] Unittests
- [ ] Github Docker Container Registry 
- [ ] Sairf/csv support
- [ ] Validate Config
- [x] Add RuleID to rules


### v8.0.0
Gitleaks v8.0.0 introduces some breaking changes and feature removals. My vision for gitleaks is for the project to
follow the [unix philosophy](https://en.wikipedia.org/wiki/Unix_philosophy) -- do one thing and one thing well. 
That one thing is detecting secrets as efficiently as possible.

#### What's changed
- Swapped `go-git` for shelling out `git log -p` and `git diff` commands when scanning/protecting git repos
    - See comparison chart for why this is a good thing
- Added `detect`, `ingest`, `protect`, `help`, and `version` commands to reduce number of options
- Added new rules TODO
- Add confidence rating (low, medium, high)
- Rule's regular expressions now support multiline regular expressions
- Added `StartLine`, `EndLine`, `StartColumn`, `EndColumn` to report findings
- Added `RuleID` to report findings
- CLI powered by `spf13/cobra`
- Removed all `repo-config` support
    - This can be scripted 
- Removed cloning support
    - I do not want gitleaks to be responsible for cloning repositories
- Removed `files at commit` support
    - This can be accomplished by `git checkout`
- Removed all `commit` options
    - All commit options can be supported by the `--log-opts` argument. See TODO
- All log messages sent to stderr
- Finding output (enabled with `-v`/`--verbose` sent to stdout.
    - This can be paired with `jq` to do additional filtering
