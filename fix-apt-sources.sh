#!/bin/bash
# Script to fix apt sources.list by commenting out problematic canonical.com repository

SOURCES_FILE="/etc/apt/sources.list"

# Backup the original file
sudo cp "$SOURCES_FILE" "${SOURCES_FILE}.backup.$(date +%Y%m%d_%H%M%S)"

# Comment out canonical.com lines
sudo sed -i 's/^deb http:\/\/archive\.canonical\.com\/ubuntu/# &/' "$SOURCES_FILE"
sudo sed -i 's/^deb-src http:\/\/archive\.canonical\.com\/ubuntu/# &/' "$SOURCES_FILE"

echo "Fixed apt sources.list. Backup created."
echo "Commented out canonical.com repository lines."
echo ""
echo "Updated sources.list:"
cat "$SOURCES_FILE"
echo ""
echo "Now run: sudo apt update"



