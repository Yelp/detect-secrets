# What's New

Thanks to all our contributors, users, and the many people that make `detect-secrets` possible! :heart:

If you love `detect-secrets`, please star our project on GitHub to show your support! :star:

<!--
# A.B.C
##### MMM DDth, YYYY

#### :newspaper: News
#### :mega: Release Highlights
#### :boom: Breaking Changes
#### :tada: New Features
#### :sparkles: Usability
#### :mortar_board: Walkthrough / Help
#### :performing_arts: Performance
#### :telescope: Accuracy
#### :bug: Bugfixes
#### :snake: Miscellaneous
#### :art: Display Changes

[#xxxx]: https://github.com/Yelp/detect-secrets/pull/xxxx
[@xxxx]: https://github.com/xxxx
-->

### v0.12.5
##### July 23rd, 2019

#### :tada: New Features

- Added webhook detection to our Slack plugin ([#195], thanks [@adrianbn])
- Added support for scanning multiple files ([#188], thanks [@dgzlopes])
- Added support for scanning multiple repositories ([#193])
- Added verification for AWS and Slack secrets ([#194])
- Added an `audit --display-results` feature to aid plugin development ([#205])

#### :telescope: Accuracy

- Improved our Artifactory regex ([#195], thanks [@adrianbn])
- Improved sequential string detection to catch the Base64 character set ([#207])
- Moved our sequential string detection so it is used by all plugins ([#196])

#### :performing_arts: Performance

- Added performance testing benchmarks ([#181], [#186], [#187], thanks [@dgzlopes])

[#181]: https://github.com/Yelp/detect-secrets/pull/181
[#186]: https://github.com/Yelp/detect-secrets/pull/186
[#187]: https://github.com/Yelp/detect-secrets/pull/187
[#188]: https://github.com/Yelp/detect-secrets/pull/188
[#193]: https://github.com/Yelp/detect-secrets/pull/193
[#194]: https://github.com/Yelp/detect-secrets/pull/194
[#195]: https://github.com/Yelp/detect-secrets/pull/195
[#196]: https://github.com/Yelp/detect-secrets/pull/196
[#205]: https://github.com/Yelp/detect-secrets/pull/205
[#207]: https://github.com/Yelp/detect-secrets/pull/207



### v0.12.4
##### May 22nd, 2019

#### :newspaper: News

- `whitelist`/`blacklist` have been replaced with `allowlist`/`denylist` ([#178], thanks [@richo]).
This includes using `# pragma: allowlist secret` now for inline allowlisting.
`# pragma: whitelist secret` compatibility will be removed in a later major version bump.

#### :tada: New Features

- Added a `StripeDetector` plugin ([#169], thanks [@dgzlopes])
- Improved handling of un-scannable files ([#176], thanks [@dgzlopes])

#### :snake: Miscellaneous

- Improved documentation of regex based detector's in the README ([#177], thanks [@dgzlopes])

[#169]: https://github.com/Yelp/detect-secrets/pull/169
[#176]: https://github.com/Yelp/detect-secrets/pull/176
[#177]: https://github.com/Yelp/detect-secrets/pull/177
[#178]: https://github.com/Yelp/detect-secrets/pull/178



### v0.12.3
##### May 13th, 2019

#### :tada: New Features

- Added an `ArtifactoryDetector` plugin ([#157] and [#163], thanks [@justineyster])
- Added support for Golang string assignments in the `KeywordDetector` plugin ([#162], thanks [@baboateng])
- Added support for XML inline whitelisting comments ([#152], thanks [@killuazhu])
- Added support for text after inline whitelisting comments ([#168], thanks [@dgzlopes])

#### :bug: Bugfixes

- Fixed a bug where filetype detection failed due to an inconsistent `configparser` import ([#155], thanks [@Namburgesas])

#### :snake: Miscellaneous
- **Greatly** improved the readability of regular expressions in the `KeywordDetector` plugin, and the maintainability of the corresponding test ([#160] and [#161], thanks [@baboateng])
- Added a contribution guide ([#166], thanks [@zioalex])
- Documented all of our inline whitelisting directives ([#165] and [#172], thanks [@dgzlopes])

[#152]: https://github.com/Yelp/detect-secrets/pull/152
[#155]: https://github.com/Yelp/detect-secrets/pull/155
[#157]: https://github.com/Yelp/detect-secrets/pull/157
[#160]: https://github.com/Yelp/detect-secrets/pull/160
[#161]: https://github.com/Yelp/detect-secrets/pull/161
[#162]: https://github.com/Yelp/detect-secrets/pull/162
[#163]: https://github.com/Yelp/detect-secrets/pull/163
[#165]: https://github.com/Yelp/detect-secrets/pull/165
[#166]: https://github.com/Yelp/detect-secrets/pull/166
[#168]: https://github.com/Yelp/detect-secrets/pull/168
[#172]: https://github.com/Yelp/detect-secrets/pull/172



### v0.12.2
##### March 21st, 2019

#### :bug: Bugfixes

- Fixed a bug where the improved performance for high-entropy strings ([#144]) did not work on Python 2 ([#147])

[#147]: https://github.com/Yelp/detect-secrets/pull/147



### v0.12.1
##### March 21st, 2019

#### :tada: New Features

- Added a `--keyword-exclude` argument to `scan` ([#132], thanks [@hpandeycodeit])

#### :telescope: Accuracy

- For the `KeywordDetector` plugin: made quotes required for secrets in `.cls` and `.java` files, and skipped `{{secrets like this}}` in YAML files ([#133]/[#145])

#### :performing_arts: Performance

- Improved performance when scanning for high-entropy strings ([#144], thanks [@killuazhu])

#### :bug: Bugfixes

- Fixed an uncaught `UnicodeEncodeError` exception in our `ini` file parser, when using Python 2 ([#143])

#### :snake: Miscellaneous

- Fixed the example pre-commit configuration in the README ([#135], thanks [@nymous]) ([#138], thanks [@neunkasulle])
- Refactored some `audit` code into `CodeSnippet` and `CodeSnippetHighlighter` classes ([#137])

[#132]: https://github.com/Yelp/detect-secrets/pull/132
[#133]: https://github.com/Yelp/detect-secrets/pull/133
[#135]: https://github.com/Yelp/detect-secrets/pull/135
[#137]: https://github.com/Yelp/detect-secrets/pull/137
[#138]: https://github.com/Yelp/detect-secrets/pull/138
[#143]: https://github.com/Yelp/detect-secrets/pull/143
[#144]: https://github.com/Yelp/detect-secrets/pull/144
[#145]: https://github.com/Yelp/detect-secrets/pull/145



### v0.12.0
##### February 11th, 2019

#### :tada: New Features

- Added a `SlackDetector` plugin ([#122], thanks [@killuazhu])
- Added a `--use-all-plugins` argument to `--update` that adds all plugins to the baseline ([#124], thanks [@killuazhu])
- Added `--exclude-files` and `--exclude-lines` arguments to `scan` ([#127])

#### :boom: Breaking Changes

- Removed the `--exclude` CLI scan argument ([#127])

#### :telescope: Accuracy

- Reduced false-positives by excluding more characters (`!$&\';`) in the `BasicAuthDetector` regex ([#126], [#123], thanks [@killuazhu])
- Added more to the `FALSE_POSITIVES` dict for the `KeywordDetector` plugin, **including** `password` ([#118])

#### :bug: Bugfixes

- Fixed a bug where `--update` was adding all plugins to the baseline, instead of respecting the plugins used in the baseline ([#124], thanks [@killuazhu])
- Fixed an uncaught `UnicodeEncodeError` exception when scanning non-ini files (e.g. markdown) containing unicode, when using Python 2 ([#128], thanks [@killuazhu])
- Fixed a bug where non-ini files (e.g. markdown) containing unicode caused a `UnicodeEncodeError` exception in the `audit` functionality, when using Python 2 ([#129], thanks [@killuazhu])
- Fixed a bug where non-posix end of line characters caused a "Secret not found on line...." error in the `audit` functionality ([#120], thanks [@killuazhu])
- Fixed a bug where `scan_diff`, called by [`detect-secrets-server`](https://github.com/Yelp/detect-secrets-server), was ignoring inline `pragma: whitelist secret` comments ([#127])

#### :snake: Miscellaneous

- Relaxed the number of spaces before inline `pragma: whitelist secret` comment ([#125], thanks [@killuazhu]]
- Added Python 3.7 to Travis CI and `tox.ini` testing ([#114], thanks [@cclauss])
- [Increased minimum test coverage from 97% to 98%](https://github.com/Yelp/detect-secrets/commit/876b523366057f8c0da14a36e3c972c3e74dfb77)

[#114]: https://github.com/Yelp/detect-secrets/pull/114
[#118]: https://github.com/Yelp/detect-secrets/pull/118
[#120]: https://github.com/Yelp/detect-secrets/pull/120
[#122]: https://github.com/Yelp/detect-secrets/pull/122
[#123]: https://github.com/Yelp/detect-secrets/pull/123
[#124]: https://github.com/Yelp/detect-secrets/pull/124
[#125]: https://github.com/Yelp/detect-secrets/pull/125
[#126]: https://github.com/Yelp/detect-secrets/pull/126
[#127]: https://github.com/Yelp/detect-secrets/pull/127
[#128]: https://github.com/Yelp/detect-secrets/pull/128
[#129]: https://github.com/Yelp/detect-secrets/pull/129



### v0.11.4
##### January 7th, 2019

#### :bug: Bugfixes
- Fixed a `TypeError` bug introduced in [#111]  ([#116])

[#116]: https://github.com/Yelp/detect-secrets/pull/116



### v0.11.3
##### January 4th, 2019

#### :bug: Bugfixes
- Fixed a bug where we were adding an extra-newline in `detect-secrets scan` output ([#111])

#### :snake: Miscellaneous

- Reorganized the code, mainly creating a `common/` directory ([#113])

[#111]: https://github.com/Yelp/detect-secrets/pull/111
[#113]: https://github.com/Yelp/detect-secrets/pull/113



### v0.11.2
##### January 4th, 2019

#### :telescope: Accuracy

- [Added `null` to the `FALSE_POSITIVES` tuple for the `KeywordDetector` plugin, so we do not alert off of it](https://github.com/Yelp/detect-secrets/commit/58df82ce37d64f22cb885960c2031b5f8ebe4b75)



### v0.11.1
##### January 4th, 2019

#### :tada: New Features

- Turned the `KeywordDetector` plugin back on, with new regexes and accuracy improvements ([#86])
- Added an `AWSAccessKeyDetector` plugin ([#100])
- Added the ability to scan `.ini` types files that do not have a header ([#106])

[#86]: https://github.com/Yelp/detect-secrets/pull/86
[#100]: https://github.com/Yelp/detect-secrets/pull/100
[#106]: https://github.com/Yelp/detect-secrets/pull/106

#### :telescope: Accuracy

- Add blacklisting of PGP private key headers in `PrivateKeyDetector` plugin ([#104])
- Reduced false-positives by improving `BasicAuthDetector` plugin regex ([#98])

[#104]: https://github.com/Yelp/detect-secrets/pull/104

#### :bug: Bugfixes
- Fixed a bug where we were not showing removed lines in the `audit` functionality ([#98])

[#98]: https://github.com/Yelp/detect-secrets/pull/98

#### :snake: Miscellaneous

- Added whitelist directive regexes to match against inline comment syntaxes in more languages ([#105])
- Refactored various detectors to use `RegexBasedDetector` ([#103])
- Refactored the `BashColor` singleton into the `colorize` function ([#109])
- Small improvements to existing file parsers ([#107])
- Refactored the `BasePlugin` to use the `WHITELIST_REGEX` ([#99])
- Removed `unidiff` from standard dependencies ([#101])

[#99]: https://github.com/Yelp/detect-secrets/pull/99
[#101]: https://github.com/Yelp/detect-secrets/pull/101
[#103]: https://github.com/Yelp/detect-secrets/pull/103
[#105]: https://github.com/Yelp/detect-secrets/pull/105
[#107]: https://github.com/Yelp/detect-secrets/pull/107
[#109]: https://github.com/Yelp/detect-secrets/pull/109



### v0.11.0
##### November 26th, 2018

#### :tada: New Features

- Made the pre-commit hook automatically update the baseline ([#96])
- Added the `audit --diff` functionality ([#95])

[#95]: https://github.com/Yelp/detect-secrets/pull/95
[#96]: https://github.com/Yelp/detect-secrets/pull/96

#### :art: Display Changes

- Added display of secret type in audit functionality ([#94])

[#94]: https://github.com/Yelp/detect-secrets/pull/94



### v0.10.5
##### October 30th, 2018

#### :art: Display Changes

- Added a "Please git add the baseline" message ([#89])
- Improved the "Unable to open baseline file" message ([#91])

[#91]: https://github.com/Yelp/detect-secrets/pull/91

#### :bug: Bugfixes

- Update `scan --update` results to only propagate `is_secret` of new secrets  ([#90])

[#90]: https://github.com/Yelp/detect-secrets/pull/90



### 0.10.4
##### October 23rd, 2018

#### :boom: Breaking Changes
- Disabled `KeywordDetector` plugin temporarily ([#89])

#### :art: Display Changes

- Ordered baseline hashes, for better diffs ([#84])
- Added a "Please git add the baseline" message ([#89])
- Improved error messages for pre-commit hook ([#85])

[#84]: https://github.com/Yelp/detect-secrets/pull/84
[#89]: https://github.com/Yelp/detect-secrets/pull/89
[#85]: https://github.com/Yelp/detect-secrets/pull/85

#### :bug: Bugfixes

- Fixed a couple bugs in the `audit` functionality, one for small files and the other case-sensitivity in the `KeywordDetector` plugin ([#83], thanks [@jkozera])

[#83]: https://github.com/Yelp/detect-secrets/pull/83



### 0.10.3
##### October 4th, 2018

#### :tada: New Features

- Added a `KeywordDetector` plugin, that was horrible and regretful ([#76])

#### :bug: Bugfixes

- Fixed a bug in `scan --update` where we would append the baseline exclude regex to itself ([#78])
- Fixed the regular expression in the `BasicAuthDetector` plugin so that it didn't run forever ([#80])
- Removed trailing whitespace from `scan` output ([#78])

#### :snake: Miscellaneous

- Added command line hints and baseline clarification in the README ([#81], thanks [@JoshuaRLi])

[#76]: https://github.com/Yelp/detect-secrets/pull/76
[#78]: https://github.com/Yelp/detect-secrets/pull/78
[#80]: https://github.com/Yelp/detect-secrets/pull/80
[#81]: https://github.com/Yelp/detect-secrets/pull/81



### 0.10.2
##### September 12th, 2018

#### :tada: New Features

- Added a (b)ack option to 'Is this a valid secret?' ([#72], thanks [@cleborys])
- Added a `BasicAuthDetector` plugin ([#74])
- Added CLI functionality to check strings in an adhoc manner ([#73])

#### :bug: Bugfixes

- Added a check to only load json from stdin if it exists ([#69], thanks [@guykisel])

#### :snake: Miscellaneous

- Fixed a typo in the README ([#68], thanks [@whathejoe])


[#68]: https://github.com/Yelp/detect-secrets/pull/68
[#69]: https://github.com/Yelp/detect-secrets/pull/69
[#72]: https://github.com/Yelp/detect-secrets/pull/72
[#73]: https://github.com/Yelp/detect-secrets/pull/73
[#74]: https://github.com/Yelp/detect-secrets/pull/74



### 0.10.1
##### August 1st, 2018

#### :bug: Bugfixes

- Fixed a bug where we didn't skip sequential strings when we should have ([#67])

[#67]: https://github.com/Yelp/detect-secrets/pull/67



### 0.10.0
##### August 1st, 2018

#### :tada: New Features

- Scan `--all-files` option ([#57])
- YAML inline whitelisting support ([#50])

#### :boom: Breaking Changes

- Changed `--audit` and `--scan` to `audit` and `scan` ([#51])
- Changed `scan --import <baseline>` to `scan --update <baseline>` ([#58])

#### :telescope: Accuracy

- Reduced false-positives caused by sequential strings, e.g. `ABCDEF` ([#64])

#### :bug: Bugfixes

- Fixed a bug where the pre-commit code would remove the `is_secret` attribute from
  audited baselines ([#65])
- Fixed an `audit` bug where we would crash if a file in the baseline did not exist
  ([#56])
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
##### June 28th, 2018

#### :bug: Bugfixes

- Fixed numbering system with interactive audit
- Fixed "leapfrog" edge case for audit functionality ([#47])


[#47]: https://github.com/Yelp/detect-secrets/pull/47



### 0.9.0
##### June 27th, 2018

#### :tada: New Features

- Added ability to migrate baselines from an older version to a newer version
- Added functionality to audit baseline, to distinguish difference between
  false and true positives in the baseline file ([#44])
- Upgraded `PrivateKeyPlugin`: more search parameters, more lines searched,
  and secret hash created using payload (rather than the entire line content)

#### :boom: Breaking Changes

- Differentiate between `Base64HighEntropyStrings` and `HexHighEntropyStrings` through
  `secret_type` ([#26])
- Got rid of `SensitivityValues` as a means to store plugin configs

#### :telescope: Accuracy

- Improved the heuristic for `HexHighEntropyStrings`, reducing the false positive rates
  for large numbers identified in code

#### :bug: Bugfixes

- Baseline always outputs in sorted order now, to prevent unnecessary diffs ([#25])
- Escape exclude regex statements before compilation ([#39])
- Fixed case where details of plugins used were not included in the baseline,
  when the pre-commit hook updated it ([#40])

#### :snake: Miscellaneous

- Simplified logging by removing `CustomLog` ([#46])


[#25]: https://github.com/Yelp/detect-secrets/pull/25
[#26]: https://github.com/Yelp/detect-secrets/pull/26
[#39]: https://github.com/Yelp/detect-secrets/pull/39
[#40]: https://github.com/Yelp/detect-secrets/pull/40
[#44]: https://github.com/Yelp/detect-secrets/pull/44
[#46]: https://github.com/Yelp/detect-secrets/pull/46



### Before 0.9.0

#### :tada: New Features

- Allow scanning of non-git files ([#18])

#### :telescope: Accuracy

- Improved scanning of INI config files with `HighEntropyString` ([#13] and [#17])
- Improved scanning of YAML files with `HighEntropyString` ([#16])

#### :bug: Bugfixes

- Fixed `PrivateKeyDetector` plugin analyze results' representation ([#15])

[#13]: https://github.com/Yelp/detect-secrets/pull/13
[#15]: https://github.com/Yelp/detect-secrets/pull/15
[#16]: https://github.com/Yelp/detect-secrets/pull/16
[#17]: https://github.com/Yelp/detect-secrets/pull/17
[#18]: https://github.com/Yelp/detect-secrets/pull/18



# Special thanks to our awesome contributors! :clap:

- [@adrianbn]
- [@baboateng]
- [@cclauss]
- [@cleborys]
- [@dgzlopes]
- [@guykisel]
- [@hpandeycodeit]
- [@jkozera]
- [@JoshuaRLi]
- [@justineyster]
- [@killuazhu]
- [@Namburgesas]
- [@neunkasulle]
- [@nymous]
- [@richo]
- [@whathejoe]
- [@zioalex]

[@adrianbn]: https://github.com/adrianbn
[@baboateng]: https://github.com/baboateng
[@cclauss]: https://github.com/cclauss
[@cleborys]: https://github.com/cleborys
[@dgzlopes]: https://github.com/dgzlopes
[@guykisel]: https://github.com/guykisel
[@hpandeycodeit]: https://github.com/hpandeycodeit
[@jkozera]: https://github.com/jkozera
[@JoshuaRLi]: https://github.com/JoshuaRLi
[@justineyster]: https://github.com/justineyster
[@killuazhu]: https://github.com/killuazhu
[@Namburgesas]: https://github.com/Namburgesas
[@neunkasulle]: https://github.com/neunkasulle
[@nymous]: https://github.com/nymous
[@richo]: https://github.com/richo
[@whathejoe]: https://github.com/whathejoe
[@zioalex]: https://github.com/zioalex
