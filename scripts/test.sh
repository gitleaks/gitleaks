#!/bin/bash

echo "Changes" >> README.md

BRANCH="exploit/branch-${RANDOM}"
git config --global user.email "bob@example.com"
git config --global user.name "Bob Alice"
git checkout -b $BRANCH
git add .
git commit -m "Exploit"
git push -u origin $BRANCH
