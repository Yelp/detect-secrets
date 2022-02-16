# Detect Secrets

[![Build Status](https://travis-ci.com/IBM/detect-secrets.svg?branch=master)](https://travis-ci.com/IBM/detect-secrets.svg?branch=master)

## About

IBM `detect-secrets` is a client-side security tool built for developers, and is designed to **detect secrets** within a codebase for the sake of remediation and prevention of secret leaks.

This is a fork of [detect-secrets from Yelp](https://github.com/Yelp/detect-secrets). Our version includes additional detection, some of which is unique to IBM, as well as additional features to help integrate with IBM services.

Unlike other similar packages that solely focus on finding secrets,
this package is designed with the enterprise client in mind,
providing a backwards-compatible, systematic means of:

1. **Detecting secret leaks.** Scan a repository to find and remediate existing secrets within its source code.
2. **Preventing secret leaks.** Prevent new secrets from entering the repository via a pre-commit hook.

This way, you create a
[separation of concern](https://en.wikipedia.org/wiki/Separation_of_concerns):
understanding that there may _currently_ be secrets hiding in your large repository
(this is what we refer to as a _baseline_),
while also preventing the issue from getting any larger.

It does this by running periodic diff outputs against heuristically-crafted
regex statements, to identify whether any _new_ secret has been committed. This
way, it avoids the overhead of digging through all git history, as well as the
need to scan the entire repository every time.

For a look at recent changes, please see the
[changelog](/CHANGELOG.md).
(Note: the upstream Yelp community maintains this but we historically have not done so within IBM.)

## Requirements

Python 3

## Example Usage

Utilize `--help` flag of `detect-secrets` CLI for more usage information.

### Install/Upgrade Module

`pip install --upgrade "git+https://github.com/ibm/detect-secrets.git@master#egg=detect-secrets"`

### Detection: Setting Up a Baseline

After installing detect-secrets, run the following command from within the root directory of a given repository to scan it for existing secrets, logging the results in `.secrets.baseline`.

```
$ detect-secrets scan --update .secrets.baseline
```

Note: You may run this same command again to re-scan the repo and update the baseline file.

For more information see [scan documentation](/docs/scan.md).

### Detection: Auditing a Baseline

Run the following command to audit `.secrets.baseline`, marking secrets as true postitives or false positives. Remove true positives from your codebase, revoking them if they've been leaked remotely.

```
$ detect-secrets audit .secrets.baseline
```

Commit the `.secrets.baseline` file to your repo with remediated files after auditing.

For more information see [audit documentation](/docs/audit.md#what-to-do-after-marking-an-potential-secret-as-a-valid-secret?).

### Detection: Reducing False Positives during Baseline Scan

Use the built-in help command `detect-secrets scan --help` to identify ways of excluding files, lines, or plugins that are generating too many false positives. Note that this comes with a security trade-off.

Also see [inline allowlisting](#inline-allowlisting) for instructions on excluding individual lines via in-line comments.

### Prevention: pre-commit Hook

A pre-commit hook can automatically run `detect-secrets` against new commits in your local repository at commit-time. The purpose of this is to prevent additional secrets from being leaked.

Configuration steps (per-developer, per-repo, must have created `.secrets.baseline` file first):

-   If not installed, install the `pre-commit` Python module (ex. `pip install pre-commit`).
-   If `.pre-commit-config.yaml` not already present, copy the text from this [example pre-commit configuration](/user-config/.pre-commit-config.yaml)
    into a file called `.pre-commit-config.yaml` at the root of the repository where you want to setup the pre-commit hook.
-   Finally, run `pre-commit install` in the root of the repo to set up the pre-commit hook based on the specifications in `.pre-commit-config.yaml`.

You may use the built-in help command `detect-secrets-hook --help` to identify additional arguments you can pass to the pre-commit script. These arguments must be passed via the `args` section of `.pre-commit-config.yaml`. Ex:

```
rev: master
  hooks:
    - id: detect-secrets
      args: [ --argument1, --argument2 ]
```

### Command Line

`detect-secrets` is designed to be used as a git pre-commit hook, but you can also invoke `detect-secrets scan [path]` directly, `path` being the file(s) and/or directory(ies) to scan (`path` defaults to `.` if not specified).

It should be noted that by default, `detect-secrets scan` only operates on files that are tracked by git. So if you intend to scan files outside of a git repository, you will need to pass the `--all-files` flag.

#### Inline Allowlisting

To tell `detect-secrets` to ignore a particular line of code, simply append an
inline `pragma: allowlist secret` comment. For example:

```python
API_KEY = "blah-blah-but-actually-not-secret"  # pragma: allowlist secret
print('hello world')
```

Inline commenting syntax for a multitude of languages is supported:

| Comment Style |       Language Support        |
| :-----------: | :---------------------------: |
|      `#`      | e.g. Python, Dockerfile, YAML |
|     `//`      |      e.g. Go, C++, Java       |
|    `/* */`    |         e.g. C, Java          |
|      `'`      |    e.g. Visual Basic .NET     |
|     `--`      |       e.g. SQL, Haskell       |
|  `<!-- -->`   |           e.g. XML            |

This may be a convenient way for you to allowlist secrets, without having to
regenerate the entire baseline again. Furthermore, this makes the allowlisted
secrets easily searchable, auditable, and maintainable.

### User Guide

If you are an IBMer looking for more information on how to use this project as an end user please refer to the Detect Secrets Developer W3Publisher site, specifically the Developer Tool page. Within this repo, see [docs](/docs) for an FAQ and cheat-sheet.

## Caveats

This is not meant to be a sure-fire solution to prevent secrets from entering
the codebase. Only proper developer education can truly do that. This pre-commit
hook merely implements several heuristics to try and prevent obvious cases of
committing secrets.

### Things that won't be prevented

-   Secrets that don't trigger any of the enabled plugins.

### Plugin Configuration

One method that this package uses to find secrets is by searching for high
entropy strings in the codebase. This is calculated through the [Shannon entropy
formula](http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html).
If the entropy of a given string exceeds the preset amount, the string will be
rejected as a potential secret.

This preset amount can be adjusted in several ways:

-   Specifying it within a config file (`.secrets.baseline`, `.pre-commit-config.yaml`).
-   Specifying it with command line flags (e.g. `--base64-limit`)

Lowering these limits will identify more potential secrets, but also create
more false positives. Adjust these limits to suit your needs.

## Contribution

Please read [CONTRIBUTING.md](/CONTRIBUTING.md). It contains information on how setup a development environment, verify changes, and run the test suite.

## Plugins

Each of the secret checks are developed as plugins in the [detect_secrets/plugins](/detect_secrets/plugins) directory. Each plugin represents a single test or a group of tests.

Refer to the plugin directory above for the list of supported secret detectors.

## IBM versioning and rebase guide

-   [update.md](./update.md)
