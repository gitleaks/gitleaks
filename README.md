# GitLeaks

## Check git repos for secrets and keys

### Features

* Search all commits on all branches in topological order
* Regex/Entropy checks

#### Installing

```bash
go get -u github.com/zricethezav/gitleaks
```

#### Usage and Explanation

![Alt Text](https://github.com/zricethezav/gifs/blob/master/gitleaks.gif)

```sh
./gitleaks {git url}
```

This will clone the target `{git url}` and run a diff on all commits. A report will be output to `{repo_name}.json`
Gitleaks scans all lines of all commit diffs and checks if there are any regular expression matches. The regexs are defined in `main.go`. For example if a line in a commit diff like `AWS_KEY='AKAI...'` exists then the value after the assignment operator will be checked for entropy. If the value is above a certain entropy threshold then we assume that the line contains a key/secret. Work largely based on  [https://people.eecs.berkeley.edu/~rohanpadhye/files/key_leaks-msr15.pdf](https://people.eecs.berkeley.edu/~rohanpadhye/files/key_leaks-msr15.pdf)

#### TODO

* Specify a target branch
* Support for custom regex
* Filter regex
* Modify entropy cutoff
