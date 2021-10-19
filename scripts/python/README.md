#### Script: "run_gitleaks_org_repos.py"

Useg this script to run gitleaks on an organization's private and public repositories:

`for repo in self.GH_ORG.get_repos("visibility=all"):`

If gitleaks output is NULL, the file will be deleted:

```
if "No leaks found" in stream.read():
                 popen(f'rm -f {report}')
```

So we will have the individual report of each private repository:
`report = path.join(location,f'{repo.name}.leaks.json')`


**How to:**

1 - [Install gitleaks](https://github.com/zricethezav/gitleaks#installation)

2 - Install python3 and [PyGithub](https://pypi.org/project/PyGithub/)

`sudo apt install -y python3 python3-pip && pip3 install PyGithub`

3 - export your github [personal api token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token) as GIT_TOKEN (env var)

 `export GIT_TOKEN=your-token-here`

4 - Download the script

`wget https://raw.githubusercontent.com/zricethezav/gitleaks/master/scripts/python/run_gitleaks_org_repos.py`

5- And... `python3 run_gitleaks_org_repos.py -o your-org-name-here`
