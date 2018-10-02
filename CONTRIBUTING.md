# Contributing Guidelines

The gitleaks project is under [GNU General Public License v3.0](LICENSE.md) and accepts
contributions via GitHub pull requests.

## How to Contribute

Open a PR. Give the PR a descriptive title. Add some comments describing whats the purpose of the PR.

__BUT before you do that!__

Make sure you pass this list of requirements.

- You've ran `go fmt`.
- You've ran `golint`.
- Your Go changes are confined to `gitleaks_test.go` and `main.go`. This is subject to change as the project evolves. Stylistically, I like having a single go file considering the size of this project (its tiny).
- You've added test cases for your changes.
- Your test pass.

