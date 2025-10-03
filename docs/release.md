# Release Process

This document outlines the release process for `detect-secrets` to ensure consistent, high-quality releases.

## Overview

The release process consists of three main phases:
1. **Preparation** - Update version, CHANGELOG, and verify tests
2. **Release** - Create and push Git tag
3. **Validation** - Verify PyPI publication and GitHub release

## Prerequisites

Before starting a release, ensure you have:
- Write access to the repository
- PyPI publish permissions (for maintainers)
- All CI checks passing on `master` branch
- No open critical bugs blocking the release

## Release Schedule

While there's no strict release schedule, we recommend:
- **Patch releases** (1.5.x) - For critical bug fixes, as needed
- **Minor releases** (1.x.0) - When significant features accumulate (every 2-3 months)
- **Major releases** (x.0.0) - For breaking changes (as needed)

## Step-by-Step Release Process

### 1. Preparation Phase

#### 1.1. Review Commits Since Last Release

```bash
# View all commits since last release
git log v1.5.0..HEAD --oneline

# View PR titles for easier categorization
git log v1.5.0..HEAD --merges --oneline
```

#### 1.2. Update CHANGELOG.md

Add a new section at the top of `CHANGELOG.md` following the existing format:

```markdown
### v1.6.0
##### Month DDth, YYYY

#### :newspaper: News
- Any major announcements (Python version support changes, deprecations, etc.)

#### :mega: Release Highlights
- Key features that deserve special attention

#### :tada: New Features
- New feature 1 ([#XXX])
- New feature 2 ([#XXX])

#### :sparkles: Usability
- Usability improvements

#### :telescope: Accuracy
- Detection accuracy improvements

#### :bug: Bugfixes
- Bug fix 1 ([#XXX])
- Bug fix 2 ([#XXX])

#### :snake: Miscellaneous
- Dependency updates
- Infrastructure improvements

[#XXX]: https://github.com/Yelp/detect-secrets/pull/XXX
```

**Tips for CHANGELOG categorization:**
- `:newspaper: News` - Breaking changes, Python version support changes
- `:mega: Release Highlights` - Major features users should know about
- `:tada: New Features` - New detectors, new CLI flags, new functionality
- `:sparkles: Usability` - UX improvements, better error messages
- `:telescope: Accuracy` - Improvements to detection accuracy (fewer false positives/negatives)
- `:bug: Bugfixes` - Bug fixes
- `:snake: Miscellaneous` - Dependency updates, CI/CD improvements, refactoring

#### 1.3. Update Version Number

Edit `detect_secrets/__version__.py`:

```python
VERSION = '1.6.0'  # Update to new version
```

#### 1.4. Commit Version and CHANGELOG Changes

```bash
git add detect_secrets/__version__.py CHANGELOG.md
git commit -m "chore: prepare release v1.6.0"
git push origin master
```

#### 1.5. Verify CI Passes

Wait for all CI checks to pass on the commit you just pushed:
- Navigate to https://github.com/Yelp/detect-secrets/actions
- Ensure all tests pass for all Python versions
- Verify `mypy` checks pass

### 2. Release Phase

#### 2.1. Create and Push Git Tag

Once CI passes, create an annotated tag:

```bash
# Create annotated tag with release notes
git tag -a v1.6.0 -m "Release v1.6.0

See CHANGELOG.md for details."

# Push the tag to trigger PyPI release workflow
git push origin v1.6.0
```

**Important:** The tag must start with `v` (e.g., `v1.6.0`) to trigger the PyPI workflow.

#### 2.2. Monitor Release Workflow

The tag push triggers `.github/workflows/pypi.yml`:
1. Navigate to https://github.com/Yelp/detect-secrets/actions
2. Find the "detect-secrets-pypi" workflow run
3. Monitor the workflow:
   - Tests run on all supported Python versions
   - Package is built
   - Package is published to PyPI

This typically takes 10-15 minutes.

### 3. Validation Phase

#### 3.1. Verify PyPI Publication

Once the workflow completes:

```bash
# Check PyPI for new version (may take a few minutes to appear)
pip index versions detect-secrets

# Or visit: https://pypi.org/project/detect-secrets/
```

#### 3.2. Create GitHub Release

1. Navigate to https://github.com/Yelp/detect-secrets/releases/new
2. Select the tag you just created (e.g., `v1.6.0`)
3. Set release title: `v1.6.0`
4. Copy the relevant section from `CHANGELOG.md` into the release description
5. Click "Publish release"

#### 3.3. Verify Installation

Test that the new version can be installed:

```bash
# Create fresh virtual environment
python3 -m venv test-env
source test-env/bin/activate

# Install from PyPI
pip install detect-secrets

# Verify version
detect-secrets --version  # Should show v1.6.0

# Cleanup
deactivate
rm -rf test-env
```

#### 3.4. Announce Release (Optional)

For significant releases, consider:
- Posting in project discussions
- Updating documentation sites
- Notifying major users/integrations

## Troubleshooting

### CI Fails After Tagging

If CI fails after you've already pushed a tag:

```bash
# Delete the tag locally and remotely
git tag -d v1.6.0
git push origin :refs/tags/v1.6.0

# Fix the issue, commit, and restart the release process
```

### PyPI Publication Fails

If the PyPI workflow fails:
1. Check the workflow logs for specific errors
2. Common issues:
   - PyPI credentials expired (contact admin)
   - Version already exists on PyPI (you'll need to bump version)
   - Package build errors (fix and re-tag)

### Version Already Exists on PyPI

PyPI doesn't allow re-uploading the same version. If you need to fix something:
1. Delete the Git tag: `git push origin :refs/tags/v1.6.0`
2. Bump to the next patch version (e.g., `v1.6.1`)
3. Update CHANGELOG with note about the issue
4. Restart release process

## Release Checklist

Use this checklist for each release (also available in `.github/RELEASE_CHECKLIST.md`):

- [ ] All CI checks passing on `master`
- [ ] No critical open issues blocking release
- [ ] CHANGELOG.md updated with all changes since last release
- [ ] Version bumped in `detect_secrets/__version__.py`
- [ ] Version bump and CHANGELOG committed to `master`
- [ ] CI passes on version bump commit
- [ ] Git tag created and pushed
- [ ] PyPI workflow completes successfully
- [ ] New version visible on https://pypi.org/project/detect-secrets/
- [ ] GitHub release created with release notes
- [ ] Installation verified with `pip install detect-secrets`

## Maintaining Regular Releases

To keep the project healthy and users happy:

1. **Review commits monthly** - Check if enough changes have accumulated
2. **Monitor issues** - Look for user requests for new releases
3. **Don't wait for perfect** - It's better to release incrementally
4. **Communicate** - Use GitHub releases to keep users informed
5. **Automate where possible** - Consider release-drafter or similar tools

## Questions or Issues?

If you encounter issues with the release process:
1. Check the GitHub Actions logs for detailed error messages
2. Review recent releases for reference
3. Open an issue with the `release` label
4. Contact project maintainers

## See Also

- [CONTRIBUTING.md](../CONTRIBUTING.md) - General contribution guidelines
- [CHANGELOG.md](../CHANGELOG.md) - Historical release notes
- [.github/workflows/pypi.yml](../.github/workflows/pypi.yml) - PyPI release workflow
