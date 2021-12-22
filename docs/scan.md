# Scanning

## What it does

`detect-secrets scan` scans the entire codebase and outputs a snapshot of currently identified secrets.

This snapshot should be stored in a baseline file and updated on an as-needed basis. The `detect-secrets-hook` - i.e. pre-commit hook - will notify you when your baseline file needs to be updated.

### Baseline file

This file contains a list of current and verified secrets along with scanning settings. After it is generated or updated, it should be [audited](./audit.md). For simplicity's sake, we'll focus on scanning in this document.

You'll find `results` object which contains files as well as potential secrets detected within them, for example:

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

Notable fields:

| Field             | Description                                                                                                                                                                                                                                                                                     |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hashed_secret`   | The hash of the detected secret. The baseline file will not record raw secrets. To see them in plaintext, run `detect-secrets audit --display-results .secrets.baseline`.                                                                                                                       |
| `is_secret`       | This field is manually set when interactively auditing a baseline file (`detect-secrets audit .secrets.baseline`). The only time it should ever be true is when a valid secret has been detected in your codebase and has been remediated. This field is for auditing / record-keeping purposes |
| `is_verified`     | Set automatically based off the result of detect-secrets validating if your secret is active. If this field is set to true, it means that the associated token is active and requires remediation.                                                                                              |
| `line_number`     | The line number that the secret is found on                                                                                                                                                                                                                                                     |
| `type`            | The secret type                                                                                                                                                                                                                                                                                 |
| `verified_result` | TODO: https://github.com/Yelp/detect-secrets/blob/b914bb656f71a9baf7c6b3a713d4a8a1eb8f4436/detect_secrets/plugins/base.py                                                                                                                                                                       |

### Secret validation

Note that not only does the scan identify potential secrets, it also verifies if certain types of secrets in your codebase are active (TODO: link to docs for secret validation information).

## What is scanned?

Only the repository's current files are scanned, past commits are excluded. It's recommended to configure the pre-commit hook(TODO: link to docs) so that it will detect-secrets will scan local changes before they are committed.

## How it's used

Running `detect-secrets scan` on its own will print a baseline to stdout. The scan output should be redirected to a baseline file with `detect-secrets scan --update .secrets.baseline`.

If you're updating an existing baseline, your previous audit results and settings will not be overwritten. If no baseline exists yet, a new one will be created automatically with the previous command (TODO: link to docs in detect-secrets for this or add the docs from w3 step 2).

## Excluding files

See the [Developer Tool FAQ](./developer-tool-faq.md#) (TODO: find exclude files heading).

## Plugins

Detect-secrets uses plugin detectors to identify specific secrets. You have the option to disable detectors, although this is not recommended. Learn more here (TODO: add link to FAQ for adjusting detectors / plugins used).

https://github.com/Yelp/detect-secrets#plugins

## Adjusting the scan

If detect-secrets is over or under-sensitive when scanning secrets in your codebase, you'll need to adjust a couple detectors. (TODO: link to or add docs).

## Code

The scanning process is found in `detect_secrets.core.scan`, and is interfaced through `SecretsCollection`.
