### 0.9.0

#### Added

- Better heuristic for `HexHighEntropyStrings`, reducing the false positive rates
  for large numbers identified in code.
- Added functionality to audit baseline, to distinguish difference between
  false and true positives in the baseline file.
- Added ability to migrate baselines from an older version to a newer version.

#### Changed

- Got rid of `SensitivityValues` as a means to store plugin configs
- Simplified logging by removing `CustomLog`
- Differentiate between Base64HighEntropyStrings and HexHighEntropyStrings through
  `secret_type`.
- Upgraded `PrivateKeyPlugin`: more search parameters, more lines searched,
  and secret hash created using payload (rather than the entire line content)

#### Fixed

- Baseline always outputs in sorted order now
- Escape exclude regex statements before compilation
- Fixed case where details of plugins used were not included in the baseline,
  when the pre-commit hook updated it.
  [#32](https://github.com/Yelp/detect-secrets/issues/32)

### Unreleased

#### Added

- Setting up Travis CI

#### Changed

- Allow scanning of non-git files
- Better scanning of YAML files and INI config files with HighEntropyString

#### Fixed

- Bug fix for PrivateKeyPlugin analyze results' representation
