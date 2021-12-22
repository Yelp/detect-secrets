# Scanning

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [What it does](#what-it-does)
  - [Baseline file](#baseline-file)
    - [Notable fields](#notable-fields)
  - [Secret verification](#secret-verification)
- [What is scanned?](#what-is-scanned)
- [How it's used](#how-its-used)
- [Excluding files](#excluding-files)
- [Plugins](#plugins)
- [Adjusting the scan](#adjusting-the-scan)
- [Code](#code)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## What it does

`detect-secrets scan` scans the entire codebase and outputs a snapshot of currently identified secrets.

This snapshot should be stored in a baseline file and updated on an as-needed basis. The `detect-secrets-hook` - i.e. pre-commit hook - will notify you when your baseline file needs to be updated.

### Baseline file

This file contains the output of a scan. This includes a list of detected secrets, plugins used during scanning and their settings, and line & file exclusion info. After the baseline file generated or updated via the `scan` command, it should be [audited](./audit.md). For simplicity's sake, we'll focus on scanning in this document.

#### Notable fields

You'll find a **`results`** object which contains lists of detected tokens under the names of files they were detected in, for example:

```json
  "results": {
    "detect_secrets/plugins/private_key.py": [
      {
        "hashed_secret": "daefe0b4345a654580dcad25c7c11ff4c944a8c0",
        "is_secret": false,
        "is_verified": false,
        "line_number": 45,
        "type": "Private Key",
        "verified_result": null
      },
```

| Field           | Description                                                                                                                                                                                                                                                                                     |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hashed_secret` | The hash of the detected secret. The baseline file will not record raw secrets. To see them in plaintext, run `detect-secrets audit --display-results .secrets.baseline`.                                                                                                                       |
| `is_secret`     | This field is manually set when interactively auditing a baseline file (`detect-secrets audit .secrets.baseline`). The only time it should ever be true is when a valid secret has been detected in your codebase and has been remediated. This field is for auditing / record-keeping purposes |
| `is_verified`   | Set automatically based off the result of detect-secrets validating if your secret is active. If this field is set to true, it means that the associated token is active and requires remediation.                                                                                              |
| `line_number`   | The line number that the secret is found on                                                                                                                                                                                                                                                     |
| `type`          | The secret                                                                                                                                                                                                                                                                                      |

### Secret verification

Not only does scanning identify potential tokens, it also verifies if certain types of tokens are active ([verifiable tokens list](./developer-tool-faq.md#what-kinds-of-tokens-does-detect-secrets-find)). I the `is_verified` field in your baseline is set to `true`, be sure to remediate the associated token and re-run the scan.

## What is scanned?

The repository's files are scanned in ther current state. Detect Secrets will not run a "deep scan" of the repository (i.e. full commit history).

It's recommended to set up the pre-commit hook ([docs](#how-do-i-set-up-the-pre-commit-hook)) so that leaks can be prevented before they reach your codebase.

## How it's used

Running `detect-secrets scan` on its own will print a baseline to stdout. The scan output should be redirected to a baseline file with `detect-secrets scan --update .secrets.baseline`.

If you're updating an existing baseline, your previous audit results and settings will not be overwritten. If no baseline exists yet, a new one will be created automatically with the previous command (TODO: link to docs in detect-secrets for this or add the docs from w3 step 2).

## Excluding files

See the [Developer Tool FAQ](./developer-tool-faq.md#) (TODO: find exclude files heading).

## Plugins

Detect-secrets uses plugin detectors to identify specific types of tokens. You have the option to disable detectors, although this is not recommended. See (What kinds ### What kinds of tokens does detect-secrets find?

Learn more here (TODO: add link to FAQ for adjusting detectors / plugins used).

https://github.com/Yelp/detect-secrets#plugins

## Adjusting the scan

If detect-secrets is over or under-sensitive when scanning secrets in your codebase, you'll need to adjust a couple detectors. (TODO: link to or add docs).

## Code

The scanning process is found in `detect_secrets.core.scan`, and is interfaced through `SecretsCollection`.
