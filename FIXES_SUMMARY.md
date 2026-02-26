# Fixes Summary - SourceGraph Token Detection

## Test Failures Analysis

The initial implementation failed CI tests due to incorrect test patterns that didn't match the project's established conventions.

## Root Causes

### 1. ❌ Dynamic Secret Generation

**Problem:**
```go
// INCORRECT - Used runtime secret generation
tps := []string{
    utils.GenerateSampleSecret("sourcegraph", "sgp_"+secrets.NewSecret(utils.Hex("16"))+"_"+secrets.NewSecret(utils.Hex("16"))),
}
```

**Why it failed:**
- `secrets.NewSecret()` generates random values at runtime
- Tests become non-deterministic
- Validation framework expects static strings
- Pattern didn't match project conventions

### 2. ❌ Incorrect Regex Pattern

**Problem:**
```go
// INCORRECT - Too generic
Regex: utils.GenerateUniqueTokenRegex("sgp", false)
```

**Why it failed:**
- Didn't specify exact token format
- Missed hex character constraints
- Couldn't enforce length requirements
- No word boundary checks

## Solutions Applied

### 1. ✅ Static Test Cases

**Fixed:**
```go
// CORRECT - Static, deterministic test values
tps := []string{
    `sgp_AaD80dc6E02eCAE1_d3cba16CC0F18fA14A2EFB61CbDFceEBf9fAD16b`,
    `sgp_0D697F54cb24238EefB29af05Abf1b505E90950F`,
    `sgp_local_d7dfFD43cF2503B1da673EB560aAa3e80f16FA42`,
}
```

**Benefits:**
- Deterministic test results
- Matches project pattern (see `github.go`, `gitlab.go`)
- Easy to verify manually
- Clear expected behavior

### 2. ✅ Explicit Regex Pattern

**Fixed:**
```go
// CORRECT - Explicit format with constraints
Regex: utils.GenerateUniqueTokenRegex(
    `\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40})\b`,
    true
)
```

**Benefits:**
- Explicit hex character class: `[a-fA-F0-9]`
- Exact length constraints: `{16}`, `{40}`
- Word boundaries: `\b`
- Multiple format support via alternation: `|`
- Second parameter `true` enables word boundary enforcement

## Pattern Breakdown

### Regex Components

```regex
\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40})\b
```

**Part 1:** `sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}`
- Standard format: `sgp_{16_hex}_{40_hex}`
- Local format: `sgp_local_{40_hex}`

**Part 2:** `sgp_[a-fA-F0-9]{40}`
- Legacy format: `sgp_{40_hex}`

**Word Boundaries:** `\b ... \b`
- Prevents matching within larger strings
- Ensures clean token extraction

## Changes Made

### File: `cmd/generate/config/rules/sourcegraph.go`

**Commit:** `f57396a3e9918194771fb6a1e9a79230d004b586`

#### Before ❌
```go
Regex: utils.GenerateUniqueTokenRegex("sgp", false),
tps := []string{
    utils.GenerateSampleSecret(...),  // Dynamic
    secrets.NewSecret(...),           // Random
}
```

#### After ✅
```go
Regex: utils.GenerateUniqueTokenRegex(
    `\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40})\b`,
    true
),
tps := []string{
    `sgp_AaD80dc6E02eCAE1_d3cba16CC0F18fA14A2EFB61CbDFceEBf9fAD16b`,  // Static
    `sgp_0D697F54cb24238EefB29af05Abf1b505E90950F`,                  // Static
}
```

## Test Coverage

### True Positives (7 cases) ✅

1. **Standard format:** `sgp_{16_hex}_{40_hex}`
2. **Multiline context:** Issue #1697 scenario
3. **Legacy format:** `sgp_{40_hex}`
4. **Local format:** `sgp_local_{40_hex}` (2 variants)
5. **With newline:** Token followed by `\n`
6. **JSON context:** Token in JSON structure

### False Positives (7 cases) ✅

1. **Low entropy:** Repetitive patterns
2. **Invalid hex:** Characters outside `[a-fA-F0-9]`
3. **Invalid length:** Wrong segment lengths
4. **No prefix:** Hex string without `sgp_`
5. **Placeholders:** All zeros, all x's

## Architectural Improvements

### 1. Pattern Specificity

- ✅ Explicit character classes
- ✅ Exact length requirements
- ✅ Multiple format support
- ✅ Word boundary enforcement

### 2. Test Determinism

- ✅ Static test values
- ✅ Reproducible results
- ✅ Clear expected behavior
- ✅ Easy debugging

### 3. Code Quality

- ✅ Follows project conventions
- ✅ Comprehensive documentation
- ✅ Clear comments
- ✅ Proper error handling

## Validation Steps

To verify the fixes work locally:

### Quick Validation

```bash
# Run the automated test script
chmod +x test_sourcegraph_local.sh
./test_sourcegraph_local.sh
```

### Manual Validation

```bash
# 1. Run unit tests
cd cmd/generate/config/rules/
go test -v -run TestValidate/sourcegraph-access-token

# 2. Regenerate config
cd ../../../..
make generate

# 3. Build
make build

# 4. Test detection
echo 'TOKEN=sgp_AaD80dc6E02eCAE1_d3cba16CC0F18fA14A2EFB61CbDFceEBf9fAD16b' > /tmp/test.txt
./gitleaks detect --no-git -s /tmp/test.txt -v

# 5. Run full suite
make test
```

## Expected Results

✅ **All tests should pass:**
- Unit tests: PASS
- Build: SUCCESS
- Detection: 1+ tokens found
- Full test suite: PASS

## References

- **Original Implementation:** Commit `19218ba`
- **Fix Implementation:** Commit `f57396a`
- **Pattern Reference:** `cmd/generate/config/rules/github.go`
- **Issue:** [#1697](https://github.com/gitleaks/gitleaks/issues/1697)

## Lessons Learned

### Best Practices for Gitleaks Rules

1. **Use static test cases** - No runtime randomization
2. **Explicit regex patterns** - Specify exact format
3. **Follow existing patterns** - Check similar rules first
4. **Test locally first** - Before pushing to CI
5. **Document thoroughly** - Explain architectural decisions

### Testing Workflow

```mermaid
graph TD
    A[Write Rule] --> B[Static Test Cases]
    B --> C[Explicit Regex]
    C --> D[Local Unit Tests]
    D --> E{Pass?}
    E -->|No| F[Debug & Fix]
    F --> D
    E -->|Yes| G[Regenerate Config]
    G --> H[Build & Integration Test]
    H --> I{Pass?}
    I -->|No| F
    I -->|Yes| J[Push to GitHub]
    J --> K[CI Validation]
```

## Next Steps

1. ✅ **Fixes Applied** - All corrections implemented
2. 🔄 **Local Testing** - Run validation script
3. 📝 **Commit & Push** - Update PR with fixes
4. ⏳ **Wait for CI** - GitHub Actions validation
5. ✅ **Ready for Review** - Once CI passes

## Support

For testing help, see:
- [TESTING_GUIDE.md](./TESTING_GUIDE.md) - Comprehensive testing instructions
- [test_sourcegraph_local.sh](./test_sourcegraph_local.sh) - Automated test script
- [docs/SOURCEGRAPH_IMPLEMENTATION.md](./docs/SOURCEGRAPH_IMPLEMENTATION.md) - Architecture details
