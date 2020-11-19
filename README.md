[![Build Status](https://travis-ci.com/Yelp/detect-secrets.svg?branch=master)](https://travis-ci.com/Yelp/detect-secrets)
[![PyPI version](https://badge.fury.io/py/detect-secrets.svg)](https://badge.fury.io/py/detect-secrets)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-ff69b4.svg)](https://github.com/Yelp/detect-secrets/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22+)
[![AMF](https://img.shields.io/badge/Donate-Charity-orange.svg)](https://www.againstmalaria.com/donation.aspx)

# detect-secrets

## About

`detect-secrets` is an aptly named module for (surprise, surprise) **detecting secrets** within a
code base.

However, unlike other similar packages that solely focus on finding secrets, this package is
designed with the enterprise client in mind: providing a **backwards compatible**, systematic
means of:

1. Preventing new secrets from entering the code base,
2. Detecting if such preventions are explicitly bypassed, and
3. Providing a checklist of secrets to roll, and migrate off to a more secure storage.

This way, you create a
[separation of concern](https://en.wikipedia.org/wiki/Separation_of_concerns):
accepting that there may *currently* be secrets hiding in your large repository
(this is what we refer to as a _baseline_), but preventing this issue from getting any larger,
without dealing with the potentially gargantuous effort of moving existing secrets away.

It does this by running periodic diff outputs against heuristically crafted regex statements,
to identify whether any *new* secret has been committed. This way, it avoids the overhead of
digging through all git history, as well as the need to scan the entire repository every time.

For a look at recent changes, please see [CHANGELOG.md](CHANGELOG.md).

If you are looking to contribute, please see [CONTRIBUTING.md](CONTRIBUTING.md).

For more detailed documentation, check out our other [documentation](docs/).

## Examples

### Quickstart:

Create a baseline of potential secrets currently found in your git repository.

```bash
$ detect-secrets scan > .secrets.baseline
```

**Scanning non-git tracked files:**

```bash
$ detect-secrets scan test_data/ --all-files > .secrets.baseline
```

### Adding New Secrets to Baseline:

This will rescan your codebase, and:

1. Update your baseline to be compatible with the latest version,
2. Add any new secrets it finds to your baseline,
3. Remove any secrets no longer in your codebase

This will also preserve any labelled secrets you have.

```bash
$ detect-secrets scan --baseline .secrets.baseline
```

For baselines older than version 0.9, just recreate it.

### Alerting off newly added secrets:

**Scanning Staged Files Only:**

```bash
$ detect-secret-hook --baseline .secrets.baseline $(git diff --staged --name-only)
```

**Scanning All Tracked Files:**

```bash
$ detect-secrets-hook --baseline .secrets.baseline $(git ls-files)
```

### Viewing All Enabled Plugins:

```bash
$ detect-secrets scan --list-all-plugins
ArtifactoryDetector
AWSKeyDetector
AzureStorageKeyDetector
BasicAuthDetector
CloudantDetector
Base64HighEntropyString
HexHighEntropyString
IbmCloudIamDetector
IbmCosHmacDetector
JwtTokenDetector
KeywordDetector
MailchimpDetector
NpmDetector
PrivateKeyDetector
SlackDetector
SoftlayerDetector
StripeDetector
TwilioKeyDetector
```

### Disabling Plugins:

```bash
$ detect-secrets scan --disable-plugin KeywordDetector --disable-plugin AWSKeyDetector
```

If you want to **only** run a specific plugin, you can do:

```bash
$ detect-secrets scan --list-all-plugins | \
    grep -v 'BasicAuthDetector' | \
    sed "s#^#--disable-plugin #g | \
    xargs detect-secrets scan test_data
```

### Auditing a Baseline:

This is an optional step to label the results in your baseline. It can be used to narrow down your
checklist of secrets to migrate, or to better configure your plugins to improve its signal-to-noise
ratio.

```bash
$ detect-secrets audit .secrets.baseline
```

## Installation

```bash
$ pip install detect-secrets
✨🍰✨
```

## Usage

`detect-secrets` comes with three different tools, and there is often confusion around which one
to use. Use this handy checklist to help you decide:

1. Do you want to add secrets to your baseline? If so, use **`detect-secrets scan`**.
2. Do you want to alert off new secrets not in the baseline? If so, use **`detect-secrets-hook`**.
3. Are you analyzing the baseline itself? If so, use **`detect-secrets audit`**.

### Adding Secrets to Baseline

```
$ detect-secrets scan --help
usage: detect-secrets scan [-h] [--string [STRING]] [--all-files]
                        [--baseline FILENAME] [--force-use-all-plugins]
                        [--base64-limit [BASE64_LIMIT]]
                        [--hex-limit [HEX_LIMIT]]
                        [--disabled-plugins DISABLED_PLUGINS] [-n]
                        [--exclude-lines EXCLUDE_LINES]
                        [--exclude-files EXCLUDE_FILES]
                        [--word-list WORD_LIST_FILE]
                        [path [path ...]]

Scans a repository for secrets in code. The generated output is compatible
with `detect-secrets-hook --baseline`.

positional arguments:
  path                  Scans the entire codebase and outputs a snapshot of
                        currently identified secrets.

optional arguments:
  -h, --help            show this help message and exit
  --string [STRING]     Scans an individual string, and displays configured
                        plugins' verdict.

scan options:
  --all-files           Scan all files recursively (as compared to only
                        scanning git tracked files).
  --baseline FILENAME   If provided, will update existing baseline by
                        importing settings from it.
  --force-use-all-plugins
                        If a baseline is provided, detect-secrets will default
                        to loading the plugins specified by that baseline.
                        However, this may also mean it doesn't perform the
                        scan with the latest plugins. If this flag is
                        provided, it will always use the latest plugins

plugin options:
  Configure settings for each secret scanning ruleset. By default, all
  plugins are enabled unless explicitly disabled.

  --base64-limit [BASE64_LIMIT]
                        Sets the entropy limit for high entropy strings. Value
                        must be between 0.0 and 8.0, defaults to 4.5.
  --hex-limit [HEX_LIMIT]
                        Sets the entropy limit for high entropy strings. Value
                        must be between 0.0 and 8.0, defaults to 3.0.
  --disabled-plugin DISABLED_PLUGIN
                        Plugin class names to disable. e.g. Base64HighEntropyString

filter options:
  Configure settings for filtering out secrets after they are flagged by the
  engine.

  -n, --no-verify       Disables additional verification of secrets via
                        network call.
  --exclude-lines EXCLUDE_LINES
                        If lines match this regex, it will be ignored.
  --exclude-files EXCLUDE_FILES
                        If filenames match this regex, it will be ignored.
  --word-list WORD_LIST_FILE
                        Text file with a list of words, if a secret contains a
                        word in the list we ignore it.
```

### Blocking Secrets not in Baseline

```
$ detect-secrets-hook --help
usage: detect-secrets-hook [-h] [-v] [--version] [--baseline FILENAME]
                          [--base64-limit [BASE64_LIMIT]]
                          [--hex-limit [HEX_LIMIT]]
                          [--disabled-plugins DISABLED_PLUGINS] [-n]
                          [--exclude-lines EXCLUDE_LINES]
                          [--exclude-files EXCLUDE_FILES]
                          [--word-list WORD_LIST_FILE]
                          [filenames [filenames ...]]

positional arguments:
  filenames             Filenames to check.

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose mode.
  --version             Display version information.
  --baseline FILENAME   Explicitly ignore secrets through a baseline generated
                        by `detect-secrets scan`

plugin options:
  Configure settings for each secret scanning ruleset. By default, all
  plugins are enabled unless explicitly disabled.

  --base64-limit [BASE64_LIMIT]
                        Sets the entropy limit for high entropy strings. Value
                        must be between 0.0 and 8.0, defaults to 4.5.
  --hex-limit [HEX_LIMIT]
                        Sets the entropy limit for high entropy strings. Value
                        must be between 0.0 and 8.0, defaults to 3.0.
  --disabled-plugins DISABLED_PLUGINS
                        Comma-delimited plugin class names to disable. e.g.
                        Base64HighEntropyString

filter options:
  Configure settings for filtering out secrets after they are flagged by the
  engine.

  -n, --no-verify       Disables additional verification of secrets via
                        network call.
  --exclude-lines EXCLUDE_LINES
                        If lines match this regex, it will be ignored.
  --exclude-files EXCLUDE_FILES
                        If filenames match this regex, it will be ignored.
  --word-list WORD_LIST_FILE
                        Text file with a list of words, if a secret contains a
                        word in the list we ignore it.
```

We recommend setting this up as a pre-commit hook. One way to do this is by using the
[pre-commit](https://github.com/pre-commit/pre-commit) framework:

```yaml
# .pre-commit-config.yaml
repos:
-   repo: https://github.com/Yelp/detect-secrets
    rev: v1.0.0
    hooks:
    -   id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
        exclude: package.lock.json
```

#### Inline Allowlisting

There are times when we want to exclude a false positive from blocking a commit

### Auditing Secrets in Baseline

```bash
$ detect-secrets audit --help
usage: detect-secrets audit [-h] [--diff] [--stats] [--json]
                         filename [filename ...]

Auditing a baseline allows analysts to label results, and optimize plugins for
the highest signal-to-noise ratio for their environment.

positional arguments:
  filename    Audit a given baseline file to distinguish the difference
              between false and true positives.

optional arguments:
  -h, --help  show this help message and exit
  --diff      Allows the comparison of two baseline files, in order to
              effectively distinguish the difference between various plugin
              configurations.
  --stats     Displays the results of an interactive auditing session which
              have been saved to a baseline file.

analytics:
  Quantify the success of your plugins based on the labelled results in your
  baseline. To be used with the statisitcs mode (--stats).

  --json      Outputs results in a machine-readable format.
```

## Configuration

This tool operates through a system of **plugins** and **filters**.

- **Plugins** find secrets in code
- **Filters** ignore false positives to increase scanning precision

You can adjust both to suit your precision/recall needs.

### Plugins

There are three different strategies we employ to try and find secrets in code:

1. Regex-based Rules

   These are the most common type of plugin, and work well with well-structured secrets.
   These secrets can optionally be [verified](docs/plugins.md#Verified%20Secrets), which increases
   scanning precision. However, solely depending on these may negatively affect the recall of your
   scan.

2. Entropy Detector

   This searches for "secret-looking" strings through a variety of heuristical approaches. This
   is great for non-structured secrets, but may require tuning to adjust the scanning precision.

3. Keyword Detector

   This ignores the secret value, and searches for variable names that are often associated with
   assigning secrets with hard-coded values. This is great for "non-secret-looking" strings (e.g.
   le3tc0de passwords), but may require tuning filters to adjust the scanning precision.

Want to find a secret that we don't currently catch? You can also (easily) develop your own
plugin, and use it with the engine! For more information, check out the
[plugin documentation](docs/plugins.md#Using%20Your%20Own%20Plugin).

### Filters

`detect-secrets` comes with several different in-built filters that may suit your needs.

#### --exclude-lines

Sometimes, you want to be able to globally allow certain lines in your scan, if they match a
specific pattern. You can specify a regex rule as such:

```bash
$ detect-secrets scan --exclude-lines 'password = (blah|fake)'
```

#### --exclude-files

Sometimes, you want to be able to ignore certain files in your scan. You can specify a regex
pattern to do so, and if the filename meets this regex pattern, it will not be scanned:

```bash
$ detect-secrets scan --exclude-files '.*\.signature$'
```

#### --word-list

If you know there are certain fake password values that you want to ignore, you can also use
this option:

```bash
$ cat wordlist.txt
not-a-real-secret
$ detect-secrets scan --word-list wordlist.txt
```

#### Inline Allowlisting

Sometimes, you want to apply an exclusion to a specific line, rather than globally excluding it.
You can do so with inline allowlisting as such:

```python
API_KEY = 'this-will-ordinarily-be-detected-by-a-plugin'    # pragma: allowlist secret
```

These comments are supported in multiple languages. e.g.

```java
const GoogleCredentialPassword = "something-secret-here";     //  pragma: allowlist secret
```

You can also use:

```python
# pragma: allowlist nextline secret
API_KEY = 'WillAlsoBeIgnored'
```

This may be a convenient way for you to ignore secrets, without needing to regenerate the entire
baseline again. If you need to explicitly search for these allowlisted secrets, you can also do:

```bash
$ detect-secrets scan --only-allowlisted
```

Want to write more custom logic to filter out false positives? Check out how to do this in
our [filters documentation](docs/filters.md#Using%20Your%20Own%20Filters).

## Caveats

This is not meant to be a sure-fire solution to prevent secrets from entering the codebase. Only
proper developer education can truly do that. This pre-commit hook merely implements several
heuristics to try and prevent obvious cases of committing secrets.

**Things That Won't Be Prevented:**

- Multi-line secrets
- Default passwords that don't trigger the `KeywordDetector` (e.g. `login = "hunter2"`)

## FAQ

### General

- **"Did not detect git repository." warning encountered, even though I'm in a git repo.**

  Check to see whether your `git` version is >= 1.8.5. If not, please upgrade it then try again.
  [More details here](https://github.com/Yelp/detect-secrets/issues/220).

### Windows

- **`detect-secrets audit` displays "Not a valid baseline file!" after creating baseline.**

  Ensure the file encoding of your baseline file is UTF-8.
  [More details here](https://github.com/Yelp/detect-secrets/issues/272#issuecomment-619187136).
