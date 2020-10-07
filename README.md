[![Build Status](https://travis.ibm.com/Whitewater/whitewater-detect-secrets.svg?token=tSTYkwXezbKBusqJ3V4L&branch=master)](https://travis.ibm.com/Whitewater/whitewater-detect-secrets)

# Whitewater Detect Secrets

## About

The purpose of the project is to **detect secrets** within a code base. This is a fork of [detect-secrets](https://github.com/Yelp/detect-secrets) from yelp. This includes additional detection, some of which is unique to IBM, as well as additional features to help integrate with IBM services.

`detect-secrets` is an aptly-named module for (surprise, surprise) **detecting
secrets** within a code base.

However, unlike other similar packages that solely focus on finding secrets,
this package is designed with the enterprise client in mind: providing a
**backwards-compatible**, systematic means of:

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

It does this by running periodic diff outputs against heuristically-crafted
regex statements, to identify whether any *new* secret has been committed. This
way, it avoids the overhead of digging through all git history, as well as the
need to scan the entire repository every time.

For a look at recent changes, please see the
[changelog](/CHANGELOG.md).

## Example Usage

### Setting Up a Baseline

```
$ detect-secrets scan > .secrets.baseline
```

### pre-commit Hook

```
$ cat .pre-commit-config.yaml
-   repo: git@github.com:Yelp/detect-secrets
    rev: v0.13.1
    hooks:
    -   id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
        exclude: .*/tests/.*
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
| `<!-- --!>` | e.g. XML |

This may be a convenient way for you to allowlist secrets, without having to
regenerate the entire baseline again. Furthermore, this makes the allowlisted
secrets easily searchable, auditable, and maintainable.

### User Guide

If you are looking for more information on how to use this project as an end user please refer to the [user guide](https://w3.ibm.com/w3publisher/detect-secrets).

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

## Contribution

Please read the [CONTRIBUTING.md](/CONTRIBUTING.md). Bellow is information on how setup the testing environment, and run the tests.

## Plugins

Each of the secret checks are developed as plugins in the [detect_secrets/plugins](/detect_secrets/plugins) directory. Each plugin represents a single test or a group of tests.

Refer to the plugin directory above for the list of supported secret detectors.

## IBM versioning and rebase guide

- [update.md](./update.md)
