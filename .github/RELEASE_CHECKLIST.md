# Release Checklist

Use this checklist when preparing a release. For detailed instructions, see [docs/release.md](../docs/release.md).

## Pre-Release

- [ ] All CI checks passing on `master` branch
- [ ] No critical open issues blocking the release
- [ ] Reviewed all commits since last release: `git log v1.5.0..HEAD --oneline`
- [ ] Identified changes that should be highlighted to users

## Preparation

- [ ] CHANGELOG.md updated with all changes since last release
  - [ ] Changes properly categorized (News, Features, Bugfixes, etc.)
  - [ ] All PR numbers linked
  - [ ] Release date set
- [ ] Version number bumped in `detect_secrets/__version__.py`
- [ ] Changes committed to `master`: `git commit -m "chore: prepare release vX.Y.Z"`
- [ ] Changes pushed: `git push origin master`
- [ ] CI passes on version bump commit

## Release

- [ ] Git tag created: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
- [ ] Git tag pushed: `git push origin vX.Y.Z`
- [ ] PyPI workflow triggered and running
- [ ] All PyPI workflow jobs completed successfully
  - [ ] Tests pass on all Python versions (3.9, 3.10, 3.11, 3.12, 3.13)
  - [ ] Package built successfully
  - [ ] Package published to PyPI

## Post-Release

- [ ] New version visible on https://pypi.org/project/detect-secrets/
- [ ] GitHub release created at https://github.com/Yelp/detect-secrets/releases/new
  - [ ] Tag selected: vX.Y.Z
  - [ ] Release title set: vX.Y.Z
  - [ ] Release notes copied from CHANGELOG.md
  - [ ] Release published
- [ ] Installation verified:
  ```bash
  python3 -m venv test-env
  source test-env/bin/activate
  pip install detect-secrets
  detect-secrets --version  # Should show new version
  deactivate
  rm -rf test-env
  ```
- [ ] (Optional) Release announced in appropriate channels

## If Issues Occur

### Tag Already Pushed But CI Failing
```bash
git tag -d vX.Y.Z
git push origin :refs/tags/vX.Y.Z
# Fix issues, then restart release process
```

### PyPI Upload Failed
- Check workflow logs for specific error
- If version already exists on PyPI, must bump to next version
- Cannot re-upload same version number to PyPI

## Version Number Guide

- **Patch** (1.5.X): Bug fixes, small improvements, no new features
- **Minor** (1.X.0): New features, enhancements, backwards compatible
- **Major** (X.0.0): Breaking changes, major refactoring

---

**Notes:**
- PyPI workflow: `.github/workflows/pypi.yml`
- Full release guide: `docs/release.md`
- Previous releases: https://github.com/Yelp/detect-secrets/releases
