# GitLeaks
#### Check git repos for secrets and keys

##### Features:
 * Search all commits on all branches in topological order
 * Regex/Entropy checks

##### Installing:
```
$ go get github.com/zricethezav/gitleaks
```

##### Usage and Explanation: 

```
$ ./gitleaks {git url}
```
This will clone the target `{git url}` and run a diff on all commits. A report will be output to `{repo_name}.json`

#### TODO
- Specify a target branch
- Support for custom regex
- Filter regex
- Modify entropy cutoff
