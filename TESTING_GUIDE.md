# Testing Guide - SourceGraph Token Detection

## Quick Start

This guide helps you validate the SourceGraph token detection implementation locally before submitting the PR.

## Prerequisites

- Go 1.21 or higher
- Make
- Git

## Testing Steps

### Option 1: Automated Testing (Recommended)

```bash
# Make the test script executable
chmod +x test_sourcegraph_local.sh

# Run the complete test suite
./test_sourcegraph_local.sh
```

This script will:
1. Run Go unit tests
2. Regenerate configuration
3. Build gitleaks
4. Test true positives
5. Test false positives
6. Run full test suite

### Option 2: Manual Step-by-Step Testing

#### Step 1: Run Unit Tests

```bash
cd cmd/generate/config/rules/
go test -v -run TestValidate/sourcegraph-access-token
```

**Expected Output:**
```
=== RUN   TestValidate/sourcegraph-access-token
--- PASS: TestValidate/sourcegraph-access-token (0.XXs)
PASS
ok      github.com/zricethezav/gitleaks/v8/cmd/generate/config/rules
```

#### Step 2: Regenerate Configuration

```bash
cd ../../../../  # Back to root
make generate
```

**Expected Output:**
```
go run cmd/generate/config/main.go config/gitleaks.toml
```

#### Step 3: Build Gitleaks

```bash
make build
```

**Expected Output:**
```
go build -ldflags "-X github.com/zricethezav/gitleaks/v8/version.Version=..."
```

#### Step 4: Test Detection

##### Test True Positives

Create a test file:

```bash
cat > /tmp/test_tokens.txt <<'EOF'
TOKEN=sgp_AaD80dc6E02eCAE1_d3cba16CC0F18fA14A2EFB61CbDFceEBf9fAD16b
environment("TOKEN", "sgp_1a2b3c4d5e6f7890_AbC123DeF456789012345678901234567890AbCd")
sgp_0D697F54cb24238EefB29af05Abf1b505E90950F
sgp_local_d7dfFD43cF2503B1da673EB560aAa3e80f16FA42
EOF
```

Run detection:

```bash
./gitleaks detect --no-git -s /tmp/test_tokens.txt -v
```

**Expected Output:**
```
Finding:     sgp_AaD80dc6E02eCAE1_d3cba16CC0F18fA14A2EFB61CbDFceEBf9fAD16b
Secret:      sgp_AaD80dc6E02eCAE1_d3cba16CC0F18fA14A2EFB61CbDFceEBf9fAD16b
RuleID:      sourcegraph-access-token
Entropy:     X.XXXXX
File:        /tmp/test_tokens.txt
Line:        1

[... more detections ...]

4 unique secrets detected
```

##### Test False Positives

```bash
cat > /tmp/test_false.txt <<'EOF'
sgp_5555555dAAAAA7777777CcccCFaaaaaaaaaaaaaa
sgp_0000000000000000_0000000000000000000000000000000000000000
sgp_xxxxxxxxxxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
EOF

./gitleaks detect --no-git -s /tmp/test_false.txt -v
```

**Expected Output:**
```
No leaks detected
```

#### Step 5: Run Full Test Suite

```bash
make test
```

**Expected Output:**
```
ok      github.com/zricethezav/gitleaks/v8/...
[All tests pass]
```

## Validation Checklist

Before pushing to GitHub, ensure:

- [ ] Unit tests pass: `go test ./cmd/generate/config/rules/`
- [ ] Configuration regenerates: `make generate`
- [ ] Build succeeds: `make build`
- [ ] True positives detected: 4+ tokens found
- [ ] False positives avoided: 0 tokens found in false positive test
- [ ] Full test suite passes: `make test`
- [ ] No linter errors: `make lint` (if available)

## Troubleshooting

### Issue: "command not found: make"

**Solution:**
```bash
# macOS
brew install make

# Ubuntu/Debian
sudo apt-get install build-essential

# Or use Go commands directly
go test ./...
go build ./cmd/gitleaks
```

### Issue: Unit tests fail

**Check:**
1. Verify regex pattern matches expected format
2. Ensure test cases have valid hex characters (a-f, A-F, 0-9)
3. Check entropy threshold (should be >= 3)

**Debug command:**
```bash
go test -v ./cmd/generate/config/rules/ -run TestValidate/sourcegraph
```

### Issue: Configuration generation fails

**Solution:**
```bash
# Clean and regenerate
rm -f config/gitleaks.toml
go run cmd/generate/config/main.go config/gitleaks.toml
```

### Issue: Build fails

**Check Go version:**
```bash
go version  # Should be 1.21 or higher
```

**Clean build:**
```bash
go clean -cache
go build ./cmd/gitleaks
```

### Issue: Detection not working as expected

**Verbose mode for debugging:**
```bash
./gitleaks detect --no-git -s test_file.txt -v --log-level trace
```

**Check regex pattern:**
```bash
grep -A 5 "sourcegraph-access-token" config/gitleaks.toml
```

## Performance Testing

### Test on Large Codebase

```bash
# Clone a large repository
git clone https://github.com/kubernetes/kubernetes /tmp/k8s

# Run gitleaks
time ./gitleaks detect -s /tmp/k8s -v

# Expected: Should complete without hanging
```

### Memory Profile

```bash
go test -memprofile=mem.prof ./cmd/generate/config/rules/
go tool pprof -http=:8080 mem.prof
```

## Integration Testing

### Test with Git Repository

```bash
# Create test repo
mkdir /tmp/test-repo && cd /tmp/test-repo
git init

# Add test file
cat > secrets.txt <<'EOF'
TOKEN=sgp_1234567890abcdef_1234567890abcdef1234567890abcdef12345678
EOF

git add secrets.txt
git commit -m "Add token"

# Run gitleaks
./gitleaks detect -s /tmp/test-repo -v
```

## Pre-Push Checklist

Before pushing to GitHub:

```bash
# 1. All tests pass
make test

# 2. Code is formatted
go fmt ./...

# 3. No vet issues
go vet ./...

# 4. Configuration is regenerated
make generate

# 5. Commit is clean
git status

# 6. Commit message follows convention
git log -1 --pretty=%B
```

## Expected Test Results Summary

| Test Category | Expected Result |
|---------------|----------------|
| Unit Tests | ✅ PASS |
| Config Generation | ✅ SUCCESS |
| Build | ✅ SUCCESS |
| True Positives | ✅ 4+ detections |
| False Positives | ✅ 0 detections |
| Full Test Suite | ✅ PASS |

## Next Steps

Once all tests pass:

1. **Commit changes:**
   ```bash
   git add .
   git commit -m "fix: correct SourceGraph token detection implementation"
   ```

2. **Push to fork:**
   ```bash
   git push origin feat/sourcegraph-token-detection
   ```

3. **Verify CI passes on GitHub**
   - Check Actions tab in your fork
   - Wait for all checks to complete

4. **Update PR if needed**
   - PR automatically updates with new commits
   - Add comment explaining fixes

## Getting Help

If you encounter issues:

1. Check the [Gitleaks documentation](https://github.com/gitleaks/gitleaks)
2. Review similar rules: `cmd/generate/config/rules/github.go`
3. Ask in the PR comments with specific error messages

## Reference

- **Issue:** [#1697](https://github.com/gitleaks/gitleaks/issues/1697)
- **Implementation:** `cmd/generate/config/rules/sourcegraph.go`
- **Documentation:** `docs/SOURCEGRAPH_IMPLEMENTATION.md`
