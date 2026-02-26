#!/bin/bash

# Script to test SourceGraph token detection locally
# Run this before submitting PR to ensure tests pass

set -e

echo "============================================"
echo "SourceGraph Token Detection - Local Testing"
echo "============================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Step 1: Run Go tests
echo "${YELLOW}Step 1: Running Go unit tests...${NC}"
cd cmd/generate/config/rules/
if go test -v -run TestValidate/sourcegraph-access-token; then
    echo "${GREEN}✓ Unit tests passed${NC}"
else
    echo "${RED}✗ Unit tests failed${NC}"
    exit 1
fi
cd -
echo ""

# Step 2: Regenerate configuration
echo "${YELLOW}Step 2: Regenerating configuration...${NC}"
if make generate; then
    echo "${GREEN}✓ Configuration regenerated successfully${NC}"
else
    echo "${RED}✗ Configuration generation failed${NC}"
    exit 1
fi
echo ""

# Step 3: Build gitleaks
echo "${YELLOW}Step 3: Building gitleaks...${NC}"
if make build; then
    echo "${GREEN}✓ Build successful${NC}"
else
    echo "${RED}✗ Build failed${NC}"
    exit 1
fi
echo ""

# Step 4: Create test files
echo "${YELLOW}Step 4: Creating test files...${NC}"
mkdir -p /tmp/gitleaks-test

# True positives - should be detected
cat > /tmp/gitleaks-test/test_true_positives.txt <<'EOF'
# True Positives - These should be detected

# Standard format
TOKEN=sgp_AaD80dc6E02eCAE1_d3cba16CC0F18fA14A2EFB61CbDFceEBf9fAD16b

# Multiline scenario from issue #1697
environment(
    "CODY_INTEGRATION_TEST_TOKEN",
    "sgp_1a2b3c4d5e6f7890_AbC123DeF456789012345678901234567890AbCd")

# Legacy format
SOURCEGRAPH_KEY=sgp_0D697F54cb24238EefB29af05Abf1b505E90950F

# Local format
API_TOKEN="sgp_local_d7dfFD43cF2503B1da673EB560aAa3e80f16FA42"

# JSON format
{"sourcegraph_token": "sgp_1A2B3C4D5E6F7890_abcdef1234567890abcdef1234567890abcdef12"}
EOF

# False positives - should NOT be detected
cat > /tmp/gitleaks-test/test_false_positives.txt <<'EOF'
# False Positives - These should NOT be detected

# Low entropy
EXAMPLE=sgp_5555555dAAAAA7777777CcccCFaaaaaaaaaaaaaa

# Invalid characters
INVALID=sgp_local_d45b6G86aBb0F2Cee943902dbaDBCFCFDD1dA089

# Placeholders
PLACEHOLDER=sgp_0000000000000000_0000000000000000000000000000000000000000
TEMPLATE=sgp_xxxxxxxxxxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Just hex without prefix
RANDOM=BcAeb6640ad7DAD46AD73687946Ce85047d5C9Bb
EOF

echo "${GREEN}✓ Test files created${NC}"
echo ""

# Step 5: Test true positives
echo "${YELLOW}Step 5: Testing true positives (should detect)...${NC}"
if ./gitleaks detect --no-git -s /tmp/gitleaks-test/test_true_positives.txt -v 2>&1 | grep -q "sourcegraph-access-token"; then
    echo "${GREEN}✓ True positives detected correctly${NC}"
    DETECTIONS=$(./gitleaks detect --no-git -s /tmp/gitleaks-test/test_true_positives.txt 2>&1 | grep -c "sourcegraph-access-token" || true)
    echo "  Found ${DETECTIONS} SourceGraph token(s)"
else
    echo "${RED}✗ Failed to detect true positives${NC}"
    echo "  Running detection for details:"
    ./gitleaks detect --no-git -s /tmp/gitleaks-test/test_true_positives.txt -v
    exit 1
fi
echo ""

# Step 6: Test false positives
echo "${YELLOW}Step 6: Testing false positives (should NOT detect)...${NC}"
if ./gitleaks detect --no-git -s /tmp/gitleaks-test/test_false_positives.txt -v 2>&1 | grep -q "sourcegraph-access-token"; then
    echo "${RED}✗ False positives detected (should not happen)${NC}"
    echo "  Detected patterns:"
    ./gitleaks detect --no-git -s /tmp/gitleaks-test/test_false_positives.txt -v | grep "sourcegraph-access-token"
    exit 1
else
    echo "${GREEN}✓ No false positives detected${NC}"
fi
echo ""

# Step 7: Run full test suite
echo "${YELLOW}Step 7: Running full test suite...${NC}"
if make test; then
    echo "${GREEN}✓ Full test suite passed${NC}"
else
    echo "${RED}✗ Test suite failed${NC}"
    exit 1
fi
echo ""

# Cleanup
echo "${YELLOW}Cleaning up test files...${NC}"
rm -rf /tmp/gitleaks-test
echo "${GREEN}✓ Cleanup complete${NC}"
echo ""

echo "============================================"
echo "${GREEN}All tests passed! ✓${NC}"
echo "============================================"
echo ""
echo "You can now:"
echo "  1. Commit your changes: git commit -am 'fix: correct implementation'"
echo "  2. Push to your fork: git push origin feat/sourcegraph-token-detection"
echo "  3. The PR will be automatically updated"
echo ""
