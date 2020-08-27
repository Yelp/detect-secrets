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

<!--
### Unreleased
-->

### v0.14.3
##### August 27th, 2020

#### :telescope: Accuracy

- Verify Slack secrets more accurately ([#325], thanks [@dryoni])

#### :bug: Bugfixes

- Fix a `TypeError` exception in adhoc string scanning ([#336])

#### :snake: Miscellaneous

- Fix an XML comment in documentation ([#322], thanks [@cilefen])

[#322]: https://github.com/Yelp/detect-secrets/pull/322
[#325]: https://github.com/Yelp/detect-secrets/pull/325
[#336]: https://github.com/Yelp/detect-secrets/pull/336
[@dryoni]: https://github.com/dryoni
[@cilefen]: https://github.com/cilefen

### v0.14.2
##### July 25th, 2020

#### :bug: Bugfixes

- Fixed an `AttributeError` exception in the pre-commit hook, when on Windows ([#321], thanks [@JohnNeville])

[#321]: https://github.com/Yelp/detect-secrets/pull/321
[@JohnNeville]: https://github.com/JohnNeville

### v0.14.1
##### July 13th, 2020

#### :bug: Bugfixes

- Add missing `tuple()` conversion that raised a `TypeError` when using `scan --update` ([#317], thanks [@shaikmanu797])

[#317]: https://github.com/Yelp/detect-secrets/pull/317
[@shaikmanu797]: https://github.com/shaikmanu797

### v0.14.0
##### July 9th, 2020

#### :mega: Release Highlights

- Remove support for Python 2 ([#292], big thanks to [@KevinHock]!)

#### :tada: New Features

- Add support for custom plugins ([#308], big thanks to [@KevinHock]!)

#### :performing_arts: Performance

- Check the allowlist after a secret is found, instead of before ([#293], [#244])

#### :telescope: Accuracy

- Make IBM plugins less noisy ([#289], thanks to [@killuazhu])

#### :bug: Bugfixes

- Display helpful eror message when scanning a baseline from a newer `detect-secrets` version ([#293], [#269])

#### :snake: Miscellaneous

- Pin coverage version used in testing ([#290])

[#244]: https://github.com/Yelp/detect-secrets/issues/244
[#269]: https://github.com/Yelp/detect-secrets/issues/269
[#289]: https://github.com/Yelp/detect-secrets/pull/289
[#290]: https://github.com/Yelp/detect-secrets/pull/290
[#292]: https://github.com/Yelp/detect-secrets/pull/292
[#293]: https://github.com/Yelp/detect-secrets/pull/293
[#308]: https://github.com/Yelp/detect-secrets/pull/308

### v0.13.1
##### March 26th, 2020

#### :tada: New Features

- Adding plugin for IBM's Cloudant ([#261], thanks [@killuazhu])
- Adding plugin for IBM Cloud Object Storage HMAC ([#263], thanks [@killuazhu])
- Adding Twilio plugin ([#267], thanks [@EdOverflow])

[#261]: https://github.com/Yelp/detect-secrets/pull/261
[#263]: https://github.com/Yelp/detect-secrets/pull/263
[#267]: https://github.com/Yelp/detect-secrets/pull/267

#### :sparkles: Usability

- Support for `DETECT_SECRETS_SECURITY_TEAM` environment variable to customize
  the pre-commit hook error message ([#283], thanks [@0atman])

[#283]: https://github.com/Yelp/detect-secrets/pull/283

#### :bug: Bugfixes

- Adhoc `HighEntropyString` scanning supports multiple words ([#287])

[#287]: https://github.com/Yelp/detect-secrets/pull/287

### v0.13.0
##### October 28th, 2019

#### :newspaper: News

- Rationale for the minor version bump:
    - Some accuracy changes that might change baselines significantly
    - @OiCMudkips' first release increases spookiness
    - It being almost Halloweeen increases spookiness

#### :tada: New Features

- Added a Softlayer plugin ([#254], thanks [@killuazhu] and [@justineyster])
- Support URL-safe base64 strings in the base64 plugin ([#245])

#### :sparkles: Usability

- Make it easier to add new plugins to detect-secrets ([#248])

#### :telescope: Accuracy

- Exclude NOPASSWD from the keyword detector ([#247], thanks [@security-architecture])
- Ignore lines with `id` in them in the high-entropy plugins ([#245])
- Ignore UUIDs detected by the base64 plugin ([#245])

#### :bug: Bugfixes

- Fix the signal metric in the audit results view ([#251])

[#245]: https://github.com/Yelp/detect-secrets/pull/245
[#247]: https://github.com/Yelp/detect-secrets/pull/247
[#248]: https://github.com/Yelp/detect-secrets/pull/248
[#251]: https://github.com/Yelp/detect-secrets/pull/251
[#254]: https://github.com/Yelp/detect-secrets/pull/254



### v0.12.7
##### September 23rd, 2019

#### :tada: New Features

- Added a `JwtTokenDetector` plugin ([#239], thanks [@gdemarcsek])
- [Added verification for Mailchimp API keys](https://github.com/Yelp/detect-secrets/pull/241/commits/977c4fb5606b42a9c73dfb598fa0a6cd0ab77c90)
- [Added verification for Stripe secret API keys](https://github.com/Yelp/detect-secrets/pull/241/commits/9cabbe078c16ce476400859ebbdf160c82f6ea80)

#### :telescope: Accuracy

- Added a `--word-list` option for filtering secrets with words in them ([#241], do `pip install detect-secrets[word_list]` to use this feature)

#### :bug: Bugfixes

- [Fixed a bug where we were not skipping ignored file extensions](https://github.com/Yelp/detect-secrets/pull/241/commits/bb543c5b20372f507ae0f99f7d01872f66db3a83)
- [Fixed a bug in the `audit` functionality where we crashed if the baseline had a Mailchimp secret in it](https://github.com/Yelp/detect-secrets/pull/241/commits/ef5d0006cc953784631f19f7de72ba3ab5972def)

[#239]: https://github.com/Yelp/detect-secrets/pull/239
[#241]: https://github.com/Yelp/detect-secrets/pull/241



### v0.12.6
##### September 16th, 2019

#### :tada: New Features

- Added a `MailchimpDetector` plugin ([#217], thanks [@dgzlopes])
- Added verification for Slack webhooks ([#233], thanks [@Patil2099])

#### :telescope: Accuracy

- Added handling of binary secrets in YAML files ([#223])
- Added various accuracy improvements to the `KeywordDetector` plugin ([#229])

#### :bug: Bugfixes

- Fixed a bug in the `audit` functionality where we crashed when the highlighter failed ([#228])
- Fixed a bug in the `audit` functionality where there was no (b)ack audit functionality when a secret was not found ([#215], thanks [@dgzlopes])
- Fixed a bug where we were not excluding SVG files ([#219])

#### :snake: Miscellaneous

- Added a unique exit code to identify baseline changes ([#214], thanks [@lirantal])
- Updated and ran our pre-commit hooks ([#221], thanks [@killuazhu])


[#214]: https://github.com/Yelp/detect-secrets/pull/214
[#215]: https://github.com/Yelp/detect-secrets/pull/215
[#217]: https://github.com/Yelp/detect-secrets/pull/217
[#219]: https://github.com/Yelp/detect-secrets/pull/219
[#221]: https://github.com/Yelp/detect-secrets/pull/221
[#223]: https://github.com/Yelp/detect-secrets/pull/223
[#228]: https://github.com/Yelp/detect-secrets/pull/228
[#229]: https://github.com/Yelp/detect-secrets/pull/229
[#233]: https://github.com/Yelp/detect-secrets/pull/233



### v0.12.5
##### July 23rd, 2019

#### :tada: New Features

- Added webhook detection to our `SlackDetector` plugin ([#195], thanks [@adrianbn])
- Added support for scanning multiple files ([#188], thanks [@dgzlopes])
- Added support for scanning multiple repositories ([#193])
- Added verification for AWS access keys and Slack tokens ([#194])
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

- [Added `null` to the `FALSE_POSITIVES` tuple for the `KeywordDetector` plugin, so we don't alert off of it](https://github.com/Yelp/detect-secrets/commit/58df82ce37d64f22cb885960c2031b5f8ebe4b75)



### v0.11.1
##### January 4th, 2019

#### :tada: New Features

- Turned the `KeywordDetector` plugin back on, with new regexes and accuracy improvements ([#86])
- Added an `AWSAccessKeyDetector` plugin ([#100])
- Added the ability to scan `.ini` types files that don't have a header ([#106])

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

- [@0atman]
- [@adrianbn]
- [@baboateng]
- [@cclauss]
- [@cleborys]
- [@dgzlopes]
- [@EdOverflow]
- [@gdemarcsek]
- [@guykisel]
- [@hpandeycodeit]
- [@jkozera]
- [@JoshuaRLi]
- [@justineyster]
- [@killuazhu]
- [@lirantal]
- [@Namburgesas]
- [@neunkasulle]
- [@nymous]
- [@Patil2099]
- [@richo]
- [@security-architecture]
- [@whathejoe]
- [@zioalex]

[@0atman]: https://github.com/0atman
[@adrianbn]: https://github.com/adrianbn
[@baboateng]: https://github.com/baboateng
[@cclauss]: https://github.com/cclauss
[@cleborys]: https://github.com/cleborys
[@dgzlopes]: https://github.com/dgzlopes
[@EdOverflow]: https://github.com/EdOverflow
[@gdemarcsek]: https://github.com/gdemarcsek
[@guykisel]: https://github.com/guykisel
[@hpandeycodeit]: https://github.com/hpandeycodeit
[@jkozera]: https://github.com/jkozera
[@JoshuaRLi]: https://github.com/JoshuaRLi
[@justineyster]: https://github.com/justineyster
[@KevinHock]: https://github.com/KevinHock
[@killuazhu]: https://github.com/killuazhu
[@lirantal]: https://github.com/lirantal
[@Namburgesas]: https://github.com/Namburgesas
[@neunkasulle]: https://github.com/neunkasulle
[@nymous]: https://github.com/nymous
[@Patil2099]: https://github.com/Patil2099
[@richo]: https://github.com/richo
[@security-architecture]: https://github.com/security-architecture
[@whathejoe]: https://github.com/whathejoe
[@zioalex]: https://github.com/zioalex
