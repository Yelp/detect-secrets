# Audit

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

-   [What is it?](#what-is-it)
-   [How to Audit a Baseline](#how-to-audit-a-baseline)
    -   [Windows Powershell and cmd](#windows-powershell-and-cmd)
    -   [Windows git bash](#windows-git-bash)
    -   [MacOS & Linux](#macos--linux)
-   [Manually Labelling Secrets](#manually-labelling-secrets)
    -   [Handling Developer Secrets](#handling-developer-secrets)
-   [What to do after marking an potential secret as a valid secret?](#what-to-do-after-marking-an-potential-secret-as-a-valid-secret)
-   [Comparing Baselines](#comparing-baselines)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## What is it?

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
