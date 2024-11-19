#!/bin/bash

echo "Changes" >> README.md

BRANCH="exploit/branch-${RAND}"
git checkout -b $BRANCH
git add .
git commit -m "Exploit"
git push -u origin $BRANCH
