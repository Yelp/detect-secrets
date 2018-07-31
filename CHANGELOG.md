### Unreleased

#### Added

- Yaml inline whitelisting support ([#50])
- Scan `--all-files` option ([#57])
- Reduced false-positives caused by sequential strings, e.g. `ABCDEF` ([#64])

#### Changed

- Changed `--audit` and `--scan` to `audit` and `scan` ([#51])
- Changed `scan --import <baseline>` to `scan --update <baseline>` ([#58])

#### Fixed

- Fixed a bug where the pre-commit code would remove the `is_secret` attribute from audited baselines ([#65])
- Fixed an `audit` bug where we would crash if a file in the baseline did not exist ([#56])
- Improved the `audit` functionality to handle short files better ([#48])


[#48]: https://github.com/Yelp/detect-secrets/pull/48
[#50]: https://github.com/Yelp/detect-secrets/pull/50
[#51]: https://github.com/Yelp/detect-secrets/pull/51
[#56]: https://github.com/Yelp/detect-secrets/pull/56
[#57]: https://github.com/Yelp/detect-secrets/pull/57
[#58]: https://github.com/Yelp/detect-secrets/pull/58
[#64]: https://github.com/Yelp/detect-secrets/pull/64
[#65]: https://github.com/Yelp/detect-secrets/pull/65


### 0.9.1
##### June 28, 2018

#### Fixed

- [Fixed "leapfrog" edge case](https://github.com/Yelp/detect-secrets/pull/47)
  for audit functionality.
- Better numbering system with interactive audit.

### 0.9.0
##### June 27, 2018

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

### Prior to 0.9.0

#### Added

- Setting up Travis CI

#### Changed

- Allow scanning of non-git files
- Better scanning of YAML files and INI config files with HighEntropyString

#### Fixed

- Bug fix for PrivateKeyPlugin analyze results' representation
