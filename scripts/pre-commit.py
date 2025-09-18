#!/usr/bin/env python3
"""Helper script to be used as a pre-commit hook."""
import subprocess
import sys

def gitleaks_enabled():
    """Check if gitleaks hook is enabled in git config."""
    out = subprocess.getoutput("git config --bool hooks.gitleaks")
    return out.lower() != "false"

def run_gitleaks():
    """Run gitleaks and return its exit code."""
    try:
        result = subprocess.run(
            ['gitleaks', 'protect', '-v', '--staged'],
            check=False
        )
        return result.returncode
    except FileNotFoundError:
        print("Error: Gitleaks is not installed.")
        return 1

if gitleaks_enabled():
    exit_code = run_gitleaks()
    if exit_code == 1:
        print('''Warning: gitleaks has detected sensitive information in your changes.
To disable the gitleaks precommit hook run the following command:

    git config hooks.gitleaks false
''')
        sys.exit(1)
else:
    print("gitleaks precommit disabled (enable with `git config hooks.gitleaks true`)")
