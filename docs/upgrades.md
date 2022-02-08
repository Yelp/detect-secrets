# Upgrades and Version Bumps

`detect-secrets` uses [semver versioning](https://semver.org/) for releases. Specifically,

1. All **code breaking** API changes will result in a MAJOR version change,
2. All **baseline modifications** and/or **features** will result in a MINOR version change,
3. All **bug fixes** will result in a PATCH version change.

This document attempts to standardize version upgrades, and provide a means to make easy,
self-documenting, backwards-compatible changes.

## When

This section provides a list of common actions, and their corresponding need for version bumps:

- **Adding a New Filter**: MINOR version bump, even if the filter does not intend to be added
  by default.

- **Adding a New Plugin**: MINOR version bump, as this will modify the baseline to include it.

- **Modifying Command Line Arguments**: MINOR version bump. While this may be a breaking change
  to the command line API, only code breaking API changes will result in a MAJOR version change.
  Otherwise, we'll have a chance of increasing major version bumps too often (i.e. the addition
  of `--exclude-files` will require a whole new major version upgrade).

- **Modifying Default Configuration Options**: (e.g. `Base64HighEntropyString` limit): PATCH
  version bump. This should only affect new baseline creations, and so this is backwards compatible
  by default.

## What

For all non-PATCH version bumps, a corresponding upgrade file needs to be written. This processes
old versions of baselines, and reformats them into newer, more compatible versions.

`detect_secrets.core.baseline.upgrade` will sequentially execute these upgrade modules. That is,
for a baseline version of `0.11.0`, and two defined upgrade modules `v0_12.py` and `v1_0.py`,
it will:

1. Upgrade from `0.11.0` to be compatible with `0.12.X`,
2. Upgrade from `0.12.X` to be compatible with `1.0.X`

## How

### Writing an Upgrade File

These upgrade files must be named as such: `detect_secrets/core/upgrades/v{major}_{minor}.py`, and
indicate the steps required to convert an older baseline to be compatible with the listed version.
For example, `v1_0.py` will take older baselines and convert them to be compatible with `v1.0.X`.

These files must also declare an `upgrade` function, which will be executed with one parameter:
the dictionary representation of an older baseline file.

It is recommended to **hard-code** values where appropriate, given that dynamic references may
change with the codebase and upgrade scripts should be static. For example, if you reference an
imported enum value in your upgrade script, and the enum value changes over time, the underlying
assumption of the upgrade script will break.

### Changing the Version

`detect-secrets` integrates with `bump2version` to make this process easier. Here's a handy
pre-bump checklist to make sure you haven't forgotten anything:

- [ ] Have you modified the CHANGELOG with the latest changes?
- [ ] Have you written an upgrade file to ensure backwards compatibility?

Then, you (as a `detect-secrets` maintainer) can run:

```bash
scripts/bump-version
```

### Pushing to PyPi

Once the tag from `scripts/bump-version` has been created and pushed to the repository, the pypi
github action will automatically start and publish the package to pypi.
