#!/bin/bash

# Script to determine the version of xt_setset package
# Used by DKMS and other build systems

# Try to get version from git tags first
if command -v git >/dev/null 2>&1 && [ -d ../.git ]; then
    # Get the latest git tag, or fall back to commit hash
    VERSION=$(git describe --tags --always --dirty 2>/dev/null)
    if [ -n "$VERSION" ]; then
        echo "$VERSION"
        exit 0
    fi
fi

# Try to get version from debian/changelog if it exists
if [ -f ../debian/changelog ]; then
    VERSION=$(head -1 ../debian/changelog | sed -n 's/.*(\([^)]*\)).*/\1/p')
    if [ -n "$VERSION" ]; then
        echo "$VERSION"
        exit 0
    fi
fi

# Fall back to a default version with timestamp
echo "1.0.0-$(date +%Y%m%d)"