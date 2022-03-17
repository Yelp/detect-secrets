# Audit

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

-   [What Is It?](#what-is-it)
-   [How to Audit a Baseline](#how-to-audit-a-baseline)
    -   [Windows Powershell and cmd](#windows-powershell-and-cmd)
    -   [Windows git bash](#windows-git-bash)
    -   [MacOS & Linux](#macos--linux)
-   [Manually Labelling Secrets](#manually-labelling-secrets)
    -   [Handling Developer Secrets](#handling-developer-secrets)
-   [What to do after marking an potential secret as a valid secret?](#what-to-do-after-marking-an-potential-secret-as-a-valid-secret)
-   [Comparing Baselines](#comparing-baselines)
-   [Report Generation](#report-generation)
    -   [Running in CI / CD](#running-in-ci--cd)
    -   [Output](#output)
    -   [Usage](#usage)
        -   [Instructions](#instructions)
        -   [Examples:](#examples)
            -   [Case: No --fail-on arguments provided](#case-no---fail-on-arguments-provided)
            -   [Case: No --fail-on arguments provided, instructions omitted](#case-no---fail-on-arguments-provided-instructions-omitted)
            -   [Case: All --fail-on arguments provided](#case-all---fail-on-arguments-provided)
            -   [Case: All --fail-on arguments provided, instructions omitted](#case-all---fail-on-arguments-provided-instructions-omitted)
            -   [Case: One --fail-on argument provided](#case-one---fail-on-argument-provided)
            -   [Case: One --fail-on argument provided, instructions omitted](#case-one---fail-on-argument-provided-instructions-omitted)
            -   [Case: No --fail-on arguments provided, json](#case-no---fail-on-arguments-provided-json)
            -   [Case: All --fail-on arguments provided, json](#case-all---fail-on-arguments-provided-json)
            -   [Case: One --fail-on argument provided, json](#case-one---fail-on-argument-provided-json)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## What Is It?

The `audit` command is a set of functionality designed for analysts to do more with
a pre-generated baseline. Some common use cases of this include:

-   **Manually labelling secrets**, to distinguish between true and false positives
-   **Comparing baselines**, to determine the effect of a certain configuration

## How to Audit a Baseline

This is an optional step to label the results in your baseline. It can be used to narrow down your checklist of secrets to migrate, or to better configure your plugins to improve its signal-to-noise ratio.

```bash
$ detect-secrets audit .secrets.baseline
```

### Windows Powershell and cmd

> Note: You can also setup a Powershell script following [doc here](./developer-tool-faq.md#powershell-docker-command-is-too-long-do-you-have-some-shortcut-for-detect-secrets) to avoid typing the long command.

```shell
docker run -it --rm -v c:/replace/with/your/folder/containing/git/repo:/code ibmcom/detect-secrets:latest audit .secrets.baseline
```

### Windows git bash

```shell
winpty docker run -it --rm -v /$(pwd):/code ibmcom/detect-secrets:latest audit .secrets.baseline
```

### MacOS & Linux

```shell
docker run -it --rm -v $(pwd):/code ibmcom/detect-secrets:latest audit .secrets.baseline
```

## Manually Labelling Secrets

```bash
$ detect-secrets scan --update .secrets.baseline
$ detect-secrets audit .secrets.baseline
Secret:      1 of 80
Filename:    README.md
Secret Type: Hex High Entropy String
----------
59:    }
60:  ],
61:  "results": {
62:    "config.env": [
63:      {
64:        "hashed_secret": "513e0a36963ae1e8431c041b744679ee578b7c44",
65:        "is_verified": false,
66:        "line_number": 1,
67:        "type": "Base64 High Entropy String"
68:      }
69:    ],
----------
Is this a valid secret? i.e. not a false-positive (y)es, (n)o, (s)kip, (q)uit:
```

> **Remediation Note**: When marking an potential secret as a valid secret, it is expected that the you have remediate secret.

There are two common cases for manual labelling:

1. Allows plugin developers to label data, to more systematically measure the success of their
   plugin (false positives v false negatives)

2. Allows developers to label data so that the security team can aggregate a count of true secrets
   to be migrated, and feed it to some reporting tool

Note that this feature merely adds metadata to the secrets found: it has no functioning impact to
preventing new secrets from being added. After all, by definition, new secrets have not been
labelled.

> **Developer Note**: If you are using this to test your plugins, you may want to run the scan
> with only a specific plugin enabled. Check out
> [how to disable plugins here](plugins.md#Disabling-Plugins).

### Handling Developer Secrets

A special side-note should be added to discuss the handling of developer "test" secrets.
Depending on the organization's risk level and secret storage infrastructure, they may have
different definitions on what constitutes as a "secret". In some places, any secret that works
is considered a secret. In other places, only secrets that affect the production environment is
considered a secret, as some secrets are required for developer testing / deployment etc.

We advise that the security team (or other such central governing body) communicate organizational
policies to clarify this distinction, if they intend to outsource this manual labelling effort to
the development teams.

As `detect-secrets` exists to keep secrets out of source code, it makes no distinction between
special types of secrets, and will treat all secrets equally. If you are looking for a more
systematic method of excluding "test" secrets, try
[writing your own filter](filters.md#Writing-Your-Own-Filter).

## What to do after marking an potential secret as a valid secret?

When auditing potential secrets in a codebase, users should be marking existing remediated secrets as "true". This is intended for historical bookkeeping purposes and assumes that the user has revoked the token / secret. Even though the user has remediated it, the secret is still in the repo's commit history.

## Comparing Baselines

```bash
$ detect-secrets scan test_data --base64-limit 4 > limit4
$ detect-secrets scan test_data --base64-limit 5 > limit5
$ detect-secrets audit --diff limit4 limit5
Secret:      1 of 8
Filename:    test_data/baseline.file
Secret Type: Base64 High Entropy String
----------
Status:      >> REMOVED <<
12:    {
13:      "name": "ArtifactoryDetector"
14:    },
15:    {
16:      "base64_limit": 4.5,
17:      "name": "Base64HighEntropyString"
18:    },
19:    {
20:      "name": "BasicAuthDetector"
21:    },
22:    {
----------
What would you like to do? (s)kip, (q)uit:
```

Another method to analyze baselines is through differential analysis. This is especially useful
when attempting to configure plugin options, as you can determine the number of secrets added /
removed between one option v another.
In this example, we tested the difference between using a limit of 4 v 5 for the
`Base64HighEntropyString`. In the example above (hard to tell, but in proper execution, AnsiColors
help highlight the difference), the string "`Base64HighEntropyString`" is flagged as a secret when
using a limit of 4, but ignored when using a limit of 5 (hence, the `REMOVED` status).
We can verify this through inline string scanning:

```bash
$ detect-secrets scan --string 'Base64HighEntropyString' --base64-limit 4
...
Base64HighEntropyString: True  (4.089)
...
```

## Report Generation

Want to generate a report with all the detect-secrets findings?

While similarly named, IBM's reporting feature fulfills a _different_ use case from [that of Yelp](https://github.com/Yelp/detect-secrets/blob/master/docs/audit.md#report-generation). IBM's implementation is intended be run in CI / CD pipelines for auditing purposes, or locally while testing. With it, certain checks would be executed against the results of a baseline file, and the resultant report would indicate any of those which failed.

### Running in CI / CD

To determine whether the CI / CD stage should pass, the report will emit an exit code.

If a report is run without any `fail-on` arguments (`detect-secrets audit --report .secrets.baseline`), it will execute all the fail checks by default, yet always emit a zero exit code—even if checks fail.

In CI / CD, it is recommended to provide all `fail-on` args:

```shell
detect-secrets audit --report --fail-on-on-unaudited fail-on-live --fail-on-on-audited-real .secrets.baseline
```

TODO: add instructions for setting up in CI / CD

### Output

By default, a table will be displayed listing secrets that failed the checks. There will also be a stats section at the top, and a summary at the bottom containing instructions on how to pass said checks. Instructions can be omitted with `--omit-instructions`.

For pure JSON output, include the `--json` flag.

### Usage

#### Instructions

For usage help, run:

```bash
$ detect-secrets audit --help
```

---

Arguments available to be used with `detect-secrets audit --report`:

| Argument                    | Description                                                                                                                                                                                                                                                                                                                            |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--fail-on-on-live`         | This condition is met when a secret has been verified to be live. To pass this check, make sure any secrets in the baseline file with a property of `"is_verified": true` have been remediated, and re-scan afterward.                                                                                                                 |
| `--fail-on-on-unaudited`    | This condition is met when there are potential secrets in the baseline file which have not been audited yet. To pass this check, run `detect-secrets audit .secrets.baseline` to audit any unaudited secrets.                                                                                                                          |
| `--fail-on-on-audited-real` | This condition is met when the baseline file contains one or more secrets which have been marked as actual secrets during the auditing stage. Secrets with a property of `"is_secret": true` meet this condition. To pass this check, remove those secrets from your code and re-scan so that they will be removed from your baseline. |
| `--json`                    | Providing this flag will cause the report output to be formatted as JSON. Mutually exclusive with `--omit-instructions`.                                                                                                                                                                                                               |
| `--omit-instructions`       | Providing this flag will omit instructions from the report. Mutually exclusive with `--json`.                                                                                                                                                                                                                                          |

#### Examples:

##### Case: No --fail-on arguments provided

Pass (exit code = 0):

```bash
$ detect-secrets audit --report .secrets.baseline

10 potential secrets in .secrets.baseline were reviewed. All checks have passed.

        - No unaudited secrets were found

        - No live secrets were found

        - No secrets that were audited as real were found

```

Fail (still exit code = 0 because of no provided `--fail-on` arguments!):

```
$ detect-secrets audit --report .secrets.baseline

10 potential secrets in .secrets.baseline were reviewed. Found 1 live secret, 1 unaudited secret, and 1 secret that was audited as real.

Failed Condition    Secret Type              Filename                                 Line
------------------  -----------------------  -------------------------------------  ------
Live                Hex High Entropy String  docs/scan.md                               49
Unaudited           Private Key              detect_secrets/plugins/private_key.py      50
Audited as real     Hex High Entropy String  docs/audit.md                              69

Failed conditions:

        - Unaudited secrets were found

                Run detect-secrets audit .secrets.baseline, and audit all potential secrets.

        - Live secrets were found

                Revoke all live secrets and remove them from the codebase. Afterwards, run detect-secrets scan --update .secrets.baseline to re-scan.

        - Audited true secrets were found

                Remove secrets meeting this condition from the codebase, and run detect-secrets scan --update .secrets.baseline to re-scan.

For additional help, run detect-secrets audit --help.

```

##### Case: No --fail-on arguments provided, instructions omitted

Fail (still exit code = 0 because of no provided `--fail-on` arguments!):

```
$ detect-secrets audit --report --omit-instructions .secrets.baseline

10 potential secrets in .secrets.baseline were reviewed. Found 1 live secret, 1 unaudited secret, and 1 secret that was audited as real.

Failed Condition    Secret Type              Filename                                 Line
------------------  -----------------------  -------------------------------------  ------
Live                Hex High Entropy String  docs/scan.md                               49
Unaudited           Private Key              detect_secrets/plugins/private_key.py      52
Audited as real     Hex High Entropy String  docs/audit.md                              69

Failed conditions:

        - Unaudited secrets were found

        - Live secrets were found

        - Audited true secrets were found

```

##### Case: All --fail-on arguments provided

Pass (exit code = 0):

```
$ detect-secrets audit --report --fail-on-live --fail-on-unaudited --fail-on-audited-real .secrets.baseline

10 potential secrets in .secrets.baseline were reviewed. All checks have passed.

        - No unaudited secrets were found

        - No live secrets were found

        - No secrets that were audited as real were found

```

Fail (exit code = 1):

```
$ detect-secrets audit --report --fail-on-live --fail-on-unaudited --fail-on-audited-real .secrets.baseline

10 potential secrets in .secrets.baseline were reviewed. Found 1 live secret, 1 unaudited secret, and 1 secret that was audited as real.

Failed Condition    Secret Type              Filename                                 Line
------------------  -----------------------  -------------------------------------  ------
Live                Hex High Entropy String  docs/scan.md                               49
Unaudited           Private Key              detect_secrets/plugins/private_key.py      52
Audited as real     Hex High Entropy String  docs/audit.md                              74

Failed conditions:

        - Unaudited secrets were found

                Run detect-secrets audit .secrets.baseline, and audit all potential secrets.

        - Live secrets were found

                Revoke all live secrets and remove them from the codebase. Afterwards, run detect-secrets scan --update .secrets.baseline to re-scan.

        - Audited true secrets were found

                Remove secrets meeting this condition from the codebase, and run detect-secrets scan --update .secrets.baseline to re-scan.

For additional help, run detect-secrets audit --help.

```

##### Case: All --fail-on arguments provided, instructions omitted

Fail (exit code = 1):

```
$ detect-secrets audit --report --fail-on-live --fail-on-unaudited --fail-on-audited-real --omit-instructions  .secrets.baseline

10 potential secrets in .secrets.baseline were reviewed. Found 1 live secret, 1 unaudited secret, and 1 secret that was audited as real.

Failed Condition    Secret Type              Filename                                 Line
------------------  -----------------------  -------------------------------------  ------
Live                Hex High Entropy String  docs/audit.md                              74
Unaudited           Hex High Entropy String  docs/scan.md                               49
Audited as real     Private Key              detect_secrets/plugins/private_key.py      52

Failed conditions:

        - Unaudited secrets were found

        - Live secrets were found

        - Audited true secrets were found

```

##### Case: One --fail-on argument provided

Pass (exit code = 0):

```
$ detect-secrets audit --report --fail-on-live .secrets.baseline

10 potential secrets in .secrets.baseline were reviewed. All checks have passed.

        - No live secrets were found

```

Fail (exit code = 1):

```
$ detect-secrets audit --report --fail-on-live .secrets.baseline

10 potential secrets in .secrets.baseline were reviewed. Found 1 live secret
Failed Condition    Secret Type              Filename        Line
------------------  -----------------------  ------------  ------
Live                Hex High Entropy String  docs/scan.md      49

Failed conditions:

        - Live secrets were found

                Revoke all live secrets and remove them from the codebase. Afterwards, run detect-secrets scan --update .secrets.baseline to re-scan.

For additional help, run detect-secrets audit --help.

```

##### Case: One --fail-on argument provided, instructions omitted

Fail (exit code = 1):

```
$ detect-secrets audit --report --fail-on-live --omit-instructions .secrets.baseline

10 potential secrets in .secrets.baseline were reviewed. Found 1 live secret
Failed Condition    Secret Type              Filename        Line
------------------  -----------------------  ------------  ------
Live                Hex High Entropy String  docs/scan.md      49

Failed conditions:

        - Live secrets were found

```

##### Case: No --fail-on arguments provided, json

Pass (exit code = 0):

```
$ detect-secrets audit --report --json .secrets.baseline
{
    "stats": {
        "reviewed": 10,
        "live": 0,
        "unaudited": 0,
        "audited_real": 0
    },
    "secrets": []
}
```

Fail (still exit code = 0 because of no provided `--fail-on` arguments!):

```
detect-secrets audit --report --json .secrets.baseline
{
    "stats": {
        "reviewed": 10,
        "live": 1,
        "unaudited": 1,
        "audited_real": 1
    },
    "secrets": [
        {
            "failed_condition": "Live",
            "filename": "docs/audit.md",
            "line": 74,
            "type": "Hex High Entropy String"
        },
        {
            "failed_condition": "Unaudited",
            "filename": "docs/scan.md",
            "line": 49,
            "type": "Hex High Entropy String"
        },
        {
            "failed_condition": "Audited as real",
            "filename": "detect_secrets/plugins/private_key.py",
            "line": 52,
            "type": "Private Key"
        }
    ]
}
```

##### Case: All --fail-on arguments provided, json

Pass (exit code = 0):

```
$ detect-secrets audit --report --json --fail-on-live --fail-on-unaudited --fail-on-audited-real .secrets.baseline
{
    "stats": {
        "reviewed": 10,
        "live": 0,
        "unaudited": 0,
        "audited_real": 0
    },
    "secrets": []
}
```

Fail (exit code = 1):

```
detect-secrets audit --report --json --fail-on-live --fail-on-unaudited --fail-on-audited-real .secrets.baseline
{
    "stats": {
        "reviewed": 10,
        "live": 1,
        "unaudited": 1,
        "audited_real": 1
    },
    "secrets": [
        {
            "failed_condition": "Live",
            "filename": "docs/audit.md",
            "line": 74,
            "type": "Hex High Entropy String"
        },
        {
            "failed_condition": "Unaudited",
            "filename": "docs/scan.md",
            "line": 49,
            "type": "Hex High Entropy String"
        },
        {
            "failed_condition": "Audited as real",
            "filename": "detect_secrets/plugins/private_key.py",
            "line": 52,
            "type": "Private Key"
        }
    ]
}
```

##### Case: One --fail-on argument provided, json

Fail (exit code = 1):

```
detect-secrets audit --report --json --fail-on-live .secrets.baseline
{
    "stats": {
        "reviewed": 10,
        "live": 1
    },
    "secrets": [
        {
            "failed_condition": "Live",
            "filename": "docs/scan.md",
            "line": 49,
            "type": "Hex High Entropy String"
        }
    ]
}
```
