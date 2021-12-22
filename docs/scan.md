# Scanning

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

-   [How It Works](#how-it-works)
    -   [Pre-commit Hook](#pre-commit-hook)
    -   [Baseline File](#baseline-file)
        -   [Notable Fields](#notable-fields)
-   [What Gets Scanned?](#what-gets-scanned)
    -   [Secret Verification](#secret-verification)
-   [How It’s Used](#how-its-used)
-   [Excluding Files](#excluding-files)
-   [Plugins](#plugins)
-   [Adjusting the Scan Sensitivity](#adjusting-the-scan-sensitivity)
-   [Code](#code)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## How It Works

`detect-secrets scan` scans the entire codebase and outputs a snapshot of currently identified secrets.

This snapshot should be stored in a baseline file and updated on an as-needed basis. The `detect-secrets-hook` - i.e. pre-commit hook - will notify you when your baseline file needs to be updated.

### Pre-commit Hook

The pre-commit hook uses Detect Secrets' scanning functionality to scan your code before it gets committed. It's recommended to set up this hook ([docs](./docs/../developer-tool-faq.md#how-do-i-set-up-the-pre-commit-hook)) to prevent leaks before they reach GitHub.

It's also known as the [`detect-secrets-hook`](./detect-secrets/pre_commit_hook.py).

### Baseline File

This file contains the output of a scan. This includes a list of detected secrets, plugins used during scanning and their settings, and line & file exclusion info. After the baseline file has been created or updated, it's a good idea to [audit](./audit.md) it. For simplicity's sake, we'll focus on scanning in this document.

#### Notable Fields

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

## What Gets Scanned?

The repository's files are scanned in ther current state. Detect Secrets will not run a "deep scan" of the repository (i.e. full commit history).

### Secret Verification

Not only does scanning identify potential tokens, it also verifies if certain types of tokens are active ([verifiable tokens list](./developer-tool-faq.md#what-kinds-of-tokens-does-detect-secrets-find)). If any `is_verified` fields in your baseline are set to `true`, be sure to remediate the associated tokens and re-run the scan.

## How It’s Used

Running `detect-secrets scan` on its own will print a baseline to stdout. The scan output should be redirected to a baseline file using `detect-secrets scan --update .secrets.baseline`.

If you're updating an existing baseline, your previous auditing results and settings will not be overwritten. If no baseline file exists, a new one will be created automatically using the above command.

## Excluding Files

Detect Secrets gives you the option to [exclude files from being scanned](./developer-tool-faq.md#exclude-some-files-with-the-exclude-files-option) as well [allowlist](./developer-tool-faq.md#how-do-i-use-inline-allowlisting) specfici lines of code.

## Plugins

Detect-secrets uses [plugin detectors](./README.md#plugins) to identify certain types of secrets. You have the option to disable detectors, although this is not recommended (see `detect-secrets scan --help `).

## Adjusting the Scan Sensitivity

If Detect Secrets is being overly-sensitive or not sensitive enough when scanning for secrets, you'll need to adjust some settings. See [`detect-secrets` generates too many false positives. What should I do?](#detect-secrets-generates-too-many-false-positives-what-should-i-do) to learn more about what you can do to fix this.

## Code

The scanning process is found in [`detect_secrets.core.scan`], and is interfaced through `SecretsCollection`.
