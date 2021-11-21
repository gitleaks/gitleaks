#!/usr/bin/env python
import os,sys
import subprocess

def gitleaksEnabled():
    out = subprocess.getoutput("git config --bool hooks.gitleaks")
    if out == "false":
        return False
    return True

if gitleaksEnabled():
    exitCode = os.WEXITSTATUS(os.system('gitleaks protect -v --staged'))
    if exitCode == 1:
        print('''Warning: gitleaks has detected sensitive information in your changes.
To disable the gitleaks precommit hook run the following command:

    git config hooks.gitleaks false
''')
else:
    print('gitleaks precommit disabled (enable with `git config hooks.gitleaks true`)')

