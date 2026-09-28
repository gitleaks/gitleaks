### Description:

Add opt-in `--use-fingerprint-v2` mode for content-specific `.gitleaksignore` entries and redaction-safe baseline comparisons. V2 tokens hash the finding location and raw secret, so rotating a secret at the same file, rule, and line produces a different token without storing the secret in the ignore file.

In V2 mode, legacy location-only ignore entries no longer suppress findings; regenerate those entries using the V2 tokens emitted by a scan. This makes migration explicit and ensures a stale legacy entry cannot silently hide a replacement secret. With the flag off, legacy ignore behavior remains unchanged. Redacted baseline scans compare V2 tokens from the baseline or derive them from older baselines that still contain the original secret. If a legacy redacted baseline has no recoverable identity, V2 mode reports the finding and asks the user to regenerate that baseline.

The V2 token is included in text, JSON, CSV, and template reports, and is computed before output redaction.

Fixes #2239

### Checklist:

* [x] Does your PR pass tests? `go test ./detect ./report`; `go build -o gitleaks .`
* [x] Have you written new tests for your changes? Yes; replacement-secret, legacy-ignore migration, malformed-token, and redacted-baseline cases.
* [ ] Have you lint your code locally prior to submission? `golangci-lint` is not installed in the environment.

AI assistance was used to investigate the issue and prepare this change; the contribution should be reviewed by a human maintainer.
