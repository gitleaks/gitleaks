# Enhanced GitHub Actions Examples

This directory contains enhanced GitHub Actions workflow examples demonstrating security best practices for integrating gitleaks into your CI/CD pipeline.

## 📁 Files

- `github-actions-advanced.yml` - Production-ready workflow with GitHub Advanced Security integration

## 🚀 Features

### GitHub Advanced Security Integration
The example workflow includes SARIF output support, enabling seamless integration with GitHub's security dashboard. This allows you to:

- View all detected secrets in the Security → Code scanning alerts tab
- Track secret detection trends over time
- Export findings for compliance reporting

### Multiple Scan Strategies

The workflow supports three scan modes via `workflow_dispatch`:

| Mode | Use Case | Description |
|------|----------|-------------|
| `full` | Initial setup | Scan entire git history |
| `incremental` | PR checks | Scan only new commits |
| `baseline` | Gradual adoption | Use baseline to ignore existing issues |

### Job Summary

The workflow generates a helpful job summary that appears in:
- Pull request checks
- Workflow run summaries
- Provides clear next steps when issues are found

## 🛠️ Usage

### Basic Setup

1. Copy `github-actions-advanced.yml` to your repository's `.github/workflows/` directory
2. Customize the trigger events (branches, paths) as needed
3. Commit and push

### Organization Setup

If you're using this in an organization repository, you'll need a Gitleaks license:

1. Purchase a license at [gitleaks.io](https://gitleaks.io)
2. Add `GITLEAKS_LICENSE` as a repository or organization secret
3. The workflow will automatically use it

### Personal Repositories

For personal repositories, the license is not required. Simply remove or comment out the `GITLEAKS_LICENSE` line.

## 📋 Configuration Options

### Using a Custom Configuration

To use a custom gitleaks configuration file:

```yaml
env:
  GITLEAKS_CONFIG: .gitleaks.toml  # Path to your custom config
```

### Baseline Mode

For gradual adoption in existing repositories with many legacy secrets:

```bash
# Generate baseline from existing issues
gitleaks git --baseline-path gitleaks-baseline.json

# Commit the baseline file
git add gitleaks-baseline.json
git commit -m "Add gitleaks baseline for gradual adoption"
```

Then update the workflow to use the baseline:

```yaml
args: |
  --baseline-path gitleaks-baseline.json
```

## 🔒 Security Best Practices

1. **Never disable on failure** - Secrets should block deployments
2. **Use fetch-depth: 0** - Required for accurate git history scanning
3. **Rotate exposed secrets immediately** - Don't just suppress findings
4. **Regular baseline updates** - Review and update baselines quarterly
5. **Combine with pre-commit hooks** - Catch secrets before they reach CI

## 🆘 Troubleshooting

### High False Positive Rate

Create a `.gitleaks.toml` to customize rules:

```toml
[allowlist]
paths = [
  "testdata/",
  "_test.go",
  "\\.md$"
]
regexes = [
  "EXAMPLE_KEY",
  "test-token"
]
```

### Out of Memory on Large Repositories

For very large repositories, consider:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 100  # Limit to recent commits
```

Or use the `--max-target-megabytes` flag to skip large files.

## 📖 Additional Resources

- [Official Gitleaks Documentation](https://github.com/gitleaks/gitleaks)
- [GitHub Advanced Security](https://docs.github.com/en/code-security)
- [SARIF Format](https://sarifweb.azurewebsites.net/)

---

**Contributing**: Have an improvement? We'd love to see it! Please open a PR with your enhancements.
