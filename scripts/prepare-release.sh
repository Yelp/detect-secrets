#!/usr/bin/env bash
# Script to help prepare a new release
# Usage: ./scripts/prepare-release.sh [version]
# Example: ./scripts/prepare-release.sh 1.6.0

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check if version is provided
if [ -z "$1" ]; then
    error "Usage: $0 <version>\nExample: $0 1.6.0"
fi

NEW_VERSION="$1"
VERSION_TAG="v${NEW_VERSION}"

# Validate version format (basic check)
if ! [[ $NEW_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    error "Invalid version format. Expected: X.Y.Z (e.g., 1.6.0)"
fi

info "Preparing release ${VERSION_TAG}"

# Check we're on master branch
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "master" ]; then
    warning "You're on branch '${CURRENT_BRANCH}', not 'master'"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        error "Aborted"
    fi
fi

# Check for uncommitted changes
if ! git diff-index --quiet HEAD --; then
    error "You have uncommitted changes. Please commit or stash them first."
fi

# Pull latest changes
info "Pulling latest changes from origin..."
git pull origin master

# Check if tag already exists
if git rev-parse "$VERSION_TAG" >/dev/null 2>&1; then
    error "Tag ${VERSION_TAG} already exists!"
fi

# Get current version
CURRENT_VERSION=$(python3 -c "import sys; sys.path.insert(0, '.'); from detect_secrets.__version__ import VERSION; print(VERSION)")
info "Current version: ${CURRENT_VERSION}"
info "New version: ${NEW_VERSION}"

# Get last release tag
LAST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "none")
info "Last release tag: ${LAST_TAG}"

# Show commits since last release
if [ "$LAST_TAG" != "none" ]; then
    echo ""
    info "Commits since ${LAST_TAG}:"
    echo "----------------------------------------"
    git log ${LAST_TAG}..HEAD --oneline --no-merges | head -20
    echo "----------------------------------------"
    COMMIT_COUNT=$(git log ${LAST_TAG}..HEAD --oneline --no-merges | wc -l)
    info "Total commits since last release: ${COMMIT_COUNT}"
    echo ""
fi

# Update version file
info "Updating detect_secrets/__version__.py..."
sed -i.bak "s/VERSION = '.*'/VERSION = '${NEW_VERSION}'/" detect_secrets/__version__.py
rm detect_secrets/__version__.py.bak

success "Version updated to ${NEW_VERSION}"

# Remind about CHANGELOG
echo ""
warning "IMPORTANT: You need to manually update CHANGELOG.md!"
echo ""
info "Steps to update CHANGELOG.md:"
echo "1. Add new section at the top with version ${NEW_VERSION}"
echo "2. Categorize commits since ${LAST_TAG}"
echo "3. Add proper emoji headers (:tada:, :bug:, :sparkles:, etc.)"
echo "4. Link all PR numbers"
echo ""
info "See docs/release.md for CHANGELOG format"
echo ""

# Ask if user wants to edit CHANGELOG now
read -p "Open CHANGELOG.md in editor now? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    ${EDITOR:-vim} CHANGELOG.md
fi

# Check if CHANGELOG was actually updated
if ! grep -q "### v${NEW_VERSION}" CHANGELOG.md; then
    warning "CHANGELOG.md doesn't seem to contain v${NEW_VERSION} section"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        error "Aborted - please update CHANGELOG.md"
    fi
fi

# Show diff of changes
echo ""
info "Review the changes:"
echo "----------------------------------------"
git diff detect_secrets/__version__.py CHANGELOG.md
echo "----------------------------------------"
echo ""

# Confirm before committing
read -p "Commit these changes? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    warning "Changes not committed. You can commit manually:"
    echo "  git add detect_secrets/__version__.py CHANGELOG.md"
    echo "  git commit -m 'chore: prepare release ${VERSION_TAG}'"
    exit 0
fi

# Commit changes
info "Committing changes..."
git add detect_secrets/__version__.py CHANGELOG.md
git commit -m "chore: prepare release ${VERSION_TAG}"

success "Changes committed!"

# Ask about pushing
echo ""
read -p "Push to origin? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    info "Pushing to origin..."
    git push origin master
    success "Pushed to origin!"
    echo ""
    info "Next steps:"
    echo "1. Wait for CI to pass: https://github.com/Yelp/detect-secrets/actions"
    echo "2. Create and push tag:"
    echo "   git tag -a ${VERSION_TAG} -m 'Release ${VERSION_TAG}'"
    echo "   git push origin ${VERSION_TAG}"
    echo "3. Monitor PyPI release workflow"
    echo "4. Create GitHub release when PyPI succeeds"
    echo ""
    info "See docs/release.md for full instructions"
else
    warning "Changes not pushed. You can push manually:"
    echo "  git push origin master"
fi

echo ""
success "Release preparation complete!"
