[![Build Status](https://travis-ci.com/Yelp/detect-secrets.svg?branch=master)](https://travis-ci.com/Yelp/detect-secrets)
[![PyPI version](https://badge.fury.io/py/detect-secrets.svg)](https://badge.fury.io/py/detect-secrets)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-ff69b4.svg)](https://github.com/Yelp/detect-secrets/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22+)
[![AMF](https://img.shields.io/badge/Donate-Charity-orange.svg)](https://www.againstmalaria.com/donation.aspx)


# detect-secrets

## About

`detect-secrets` is an aptly named module for (surprise, surprise) **detecting
secrets** within a code base.

However, unlike other similar packages that solely focus on finding secrets,
this package is designed with the enterprise client in mind: providing a
**backwards compatible**, systematic means of:

1. Preventing new secrets from entering the code base,
2. Detecting if such preventions are explicitly bypassed, and
3. Providing a checklist of secrets to roll, and migrate off to a more secure
   storage.

This way, you create a
[separation of concern](https://en.wikipedia.org/wiki/Separation_of_concerns):
accepting that there may *currently* be secrets hiding in your large repository
(this is what we refer to as a _baseline_),
but preventing this issue from getting any larger, without dealing with the
potentially gargantuous effort of moving existing secrets away.

It does this by running periodic diff outputs against heuristically crafted
regex statements, to identify whether any *new* secret has been committed. This
way, it avoids the overhead of digging through all git history, as well as the
need to scan the entire repository every time.

For a look at recent changes, please see [CHANGELOG.md](https://github.com/Yelp/detect-secrets/blob/master/CHANGELOG.md).

If you are looking to contribute, please see [CONTRIBUTING.md](https://github.com/Yelp/detect-secrets/blob/master/CONTRIBUTING.md).


## Example Usage

### Setting Up a Baseline

```
$ detect-secrets scan > .secrets.baseline
```


### pre-commit Hook

```
$ cat .pre-commit-config.yaml
-   repo: git@github.com:Yelp/detect-secrets
    rev: v0.14.3
    hooks:
    -   id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
        exclude: package.lock.json
```


### Auditing a Baseline

```
$ detect-secrets audit .secrets.baseline
```


### Upgrading Baselines

This is only applicable for upgrading baselines that have been created after version 0.9.
For upgrading baselines lower than that version, just recreate it.

```
$ detect-secrets scan --update .secrets.baseline
```


### Command Line

`detect-secrets` is designed to be used as a git pre-commit hook, but you can also invoke `detect-secrets scan [path]` directly being `path` the file(s) and/or directory(ies) to scan (`path` defaults to `.` if not specified).

It should be noted that by default, `detect-secrets scan` only operates on files that are tracked by git. So if you intend to scan files outside of a git repository, you will need to pass the `--all-files` flag.


## Installation

There are three components that you can setup, depending on your purposes.
While all three are independent, you should pair the Secrets Baseline with
either the client-side pre-commit hook, or the server-side secret scanner.

1. **Client-side Pre-Commit Hook**, that alerts developers when they attempt
   to enter a secret in the code base.

2. **Server-side Secret Scanning**, to periodically scan tracked repositories,
   and make sure developers didn't accidentally skip the pre-commit check.

3. **Secrets Baseline**, to allowlist pre-existing secrets in the repository,
   so that they won't be continuously caught through scan iterations.


### Client-side `pre-commit` Hook

See [pre-commit](https://github.com/pre-commit/pre-commit) for instructions
to install the pre-commit framework. The example usage above has a sample
installation configuration, with a allowlisted secrets baseline.

Hooks available:

- `detect-secrets`: This hook detects and prevents high entropy strings from
  entering the codebase.

However, you can also run it manually (without the pre-commit framework) as such:

```
git diff --staged --name-only | xargs detect-secrets-hook
```

### Server-side Secret Scanning

Please see the [detect-secrets-server](https://github.com/Yelp/detect-secrets-server)
repository for installation instructions.


### Secrets Baseline

```
$ pip install detect-secrets
✨🍰✨
```

Remember to initialize your baseline with the same plugin configurations
as your pre-commit hook, and server-side secret scanner!

#### Inline Allowlisting

To tell `detect-secrets` to ignore a particular line of code, simply append an
inline `pragma: allowlist secret` comment. For example:

```python
API_KEY = "blah-blah-but-actually-not-secret"  # pragma: allowlist secret
print('hello world')
```

Inline commenting syntax for a multitude of languages is supported:

| Comment Style | Language Support |
| :---:     | :---:       |
| `#` | e.g. Python, Dockerfile, YAML |
| `//` | e.g. Go, C++, Java |
| `/* */` | e.g. C, Java|
| `'` | e.g. Visual Basic .NET|
| `--` | e.g. SQL, Haskell|
| `<!-- -->` | e.g. XML |

This may be a convenient way for you to allowlist secrets, without having to
regenerate the entire baseline again. Furthermore, this makes the allowlisted
secrets easily searchable, auditable, and maintainable.


## Currently Supported Plugins

The current heuristic searches we implement out of the box include:

* **Base64HighEntropyString**: checks for all strings matching the Base64
  character set, and alerts if their Shannon entropy is above a certain limit.

* **HexHighEntropyString**: checks for all strings matching the Hex character
  set, and alerts if their Shannon entropy is above a certain limit.

* **PrivateKeyDetector**: checks to see if any private keys are committed.

* **BasicAuthDetector**: checks to see if BasicAuth is used e.g. `https://username:password@example.com`

* **KeywordDetector**: checks to see if certain keywords are being used e.g. `password` or `secret`

* **RegexBasedDetector**: checks for any keys matching certain regular expressions (Artifactory, AWS, Slack, Stripe, Mailchimp, Twilio).

* **JwtTokenDetector**: checks for formally correct JWTs.

* **SoftlayerDetector**: checks for Softlayer tokens.

* **IbmCloudIamDetector**: checks for IBM Cloud IAM key.

* **CloudantDetector**: checks for Cloudant credentials.


See [detect_secrets/
plugins](https://github.com/Yelp/detect-secrets/tree/master/detect_secrets/plugins)
for more details.

There is also a `--custom-plugins` option in which you can bring your own plugins, e.g. `detect-secrets scan --custom-plugins testing/custom_plugins_dir/ --custom-plugins testing/hippo_plugin.py`.


## Caveats

This is not meant to be a sure-fire solution to prevent secrets from entering
the codebase. Only proper developer education can truly do that. This pre-commit
hook merely implements several heuristics to try and prevent obvious cases of
committing secrets.


### Things that won't be prevented

* Multi-line secrets
* Default passwords that don't trigger the `KeywordDetector` (e.g. `login = "hunter2"`)


### Plugin Configuration

One method that this package uses to find secrets is by searching for high
entropy strings in the codebase. This is calculated through the [Shannon entropy
formula](http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html).
If the entropy of a given string exceeds the preset amount, the string will be
rejected as a potential secret.

This preset amount can be adjusted in several ways:

* Specifying it within the config file, for server scanning.
* Specifying it with command line flags (e.g. `--base64-limit`)

Lowering these limits will identify more potential secrets, but also create
more false positives. Adjust these limits to suit your needs.
