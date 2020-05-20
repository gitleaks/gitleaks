<p align="center">
  <img alt="gitleaks" src="https://raw.githubusercontent.com/zricethezav/gifs/master/gitleakslogo.png" height="70" />
  <p align="center">
      <a href="https://travis-ci.org/zricethezav/gitleaks"><img alt="Travis" src="https://img.shields.io/travis/zricethezav/gitleaks/master.svg?style=flat-square"></a>
  </p>
</p>

Gitleaks is a SAST tool for detecting hardcoded secrets like passwords, api keys, and tokens in git repos. Gitleaks aims to be the **easy-to-use, all-in-one solution** for finding secrets, past or present, in your code. 
 
### Features:
- Scans for [commited](https://github.com/zricethezav/gitleaks/wiki/Scanning) secrets
- Scans for [uncommitted](https://github.com/zricethezav/gitleaks/wiki/Scanning#uncommitted-changes-scan) secrets as part of shifting security left
- Available [Github Action](https://github.com/marketplace/actions/gitleaks)
- Gitlab and Github API support which allows scans of whole organizations, users, and pull/merge requests
- [Custom rules](https://github.com/zricethezav/gitleaks/wiki/Configuration) via toml configuration
- High performance using [go-git](https://github.com/go-git/go-git)
- JSON and CSV reporting
- Private repo scans using key or password based authentication


## Installation, Documentation and Examples
This project is documented [here](https://github.com/zricethezav/gitleaks/wiki)


###  Sponsors ❤️
#### Corporate Sponsors
[![gammanet](https://gammanet.com/assets/images/new-design/gamma-logo.png)](https://gammanet.com/?utm_source=gitleaks&utm_medium=homepage&utm_campaign=gitleaks_promotion)

Gamma proactively detects and remediates data leaks across cloud apps. Scan your public repos for secret leaks with [Gamma](https://gammanet.com/github-demo?utm_source=gitleaks&utm_medium=homepage&utm_campaign=gitleaks_promotion)

#### Individual Sponsors 
These users are [sponsors](https://github.com/sponsors/zricethezav) of gitleaks:

[![Adam Shannon](https://github.com/adamdecaf.png?size=50)](https://github.com/adamdecaf) | [![Granville Schmidt](https://github.com/gramidt.png?size=50)](https://github.com/gramidt) | 
---|---|
----
#### Logo Attribution
The Gitleaks logo uses the Git Logo created <a href="https://twitter.com/jasonlong">Jason Long</a> is licensed under the <a href="https://creativecommons.org/licenses/by/3.0/">Creative Commons Attribution 3.0 Unported License</a>.

