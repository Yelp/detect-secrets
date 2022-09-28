# Audit

The `audit` command is a set of functionality designed for analysts to do more with
a pre-generated baseline. Some common use cases of this include:

- **Manually labelling secrets**, to distinguish between true and false positives
- **Comparing baselines**, to determine the effect of a certain configuration

Let's explore these cases in a bit more detail:

## Manually Labelling Secrets

```bash
$ detect-secrets scan test_data > .secrets.baseline
$ detect-secrets audit .secrets.baseline
Secret:      1 of 80
Filename:    test_data/baseline.file
Secret Type: Secret Keyword
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
Is this a secret that should be committed to this repository? (y)es, (n)o, (s)kip, (q)uit:
```

There are two common cases for manual labelling:

1. Allows plugin developers to label data, to more systematically measure the success of their
   plugin (false positives v false negatives)

2. Allows developers to label data so that the security team can aggregate a count of true secrets
   to be migrated, and feed it to some reporting tool

Note that this feature merely adds metadata to the secrets found: it has no functioning impact to
preventing new secrets from being added. After all, by definition, new secrets have not been
labelled.

> **Developer Note**: If you are using this to test your plugins, you may want to run the scan
  with only a specific plugin enabled. Check out
  [how to disable plugins here](plugins.md#Disabling-Plugins).

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

## Aggregating Statistics

Often, when developing plugins, you may want to calculate a variety of statistics on the labelled
data. You can do so with the `--stats` flag (or adding `--json` for machine-readability).

For example, when used in the normal mode, it will give you the precision and recall calculation
for plugins used:

```bash
$ detect-secrets audit --stats .secrets.baseline
Base64HighEntropyString:
  - Precision: 75% (3 / 4 labelled secrets)
  - Recall:    60% (3 / 5 known true secrets)
```

or, when used in `diff` mode, it will tell you the number of secrets added/removed.

```bash
$ detect-secrets audit --stats --json --diff limit4 limit5
{
    "added": 0,
    "removed": 8
}
```

## Extracting Raw Secrets

There are times you want to extract the raw secret values to run further analysis on. You can do
so with the `--raw` flag.

TODO: Example when this feature is written up.

## Report generation

Maybe, you need to generate a full report with all the detect-secrets findings. You can generate
one with the `--report` flag:

```bash
$ detect-secrets audit --report .secret.baseline
[
    {
        "category": "VERIFIED_TRUE",
        "filename": "test.properties",
        "lines": {
            "1": "secret=value",
            "6": "password=value"
        },
        "secrets": "value",
        "types": [
            "Secret Keyword"
        ]
    },
    {
        "category": "UNVERIFIED",
        "filename": "test.properties",
        "lines": {
            "2": "password=changeit",
            "5": "password=changeit"
        },
        "secrets": "changeit",
        "types": [
            "Secret Keyword"
        ]
    },
    {
        "category": "VERIFIED_TRUE",
        "filename": "test.properties",
        "lines": {
            "3": "password=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
            "4": "test=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        },
        "secrets": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
        "types": [
            "Secret Keyword",
            "JSON Web Token"
        ]
    },
    {
        "category": "VERIFIED_FALSE",
        "filename": "test.properties",
        "lines": {
            "7": "password=faketest"
        },
        "secrets": "faketest",
        "types": [
            "Secret Keyword"
        ]
    }
]
```

You can also select only the real secrets with the option `--only-real`:

```bash
$ detect-secrets audit --report --only-real .secret.baseline
[
    {
        "category": "VERIFIED_TRUE",
        "filename": "test.properties",
        "lines": {
            "1": "secret=value",
            "6": "password=value"
        },
        "secrets": "value",
        "types": [
            "Secret Keyword"
        ]
    },
    {
        "category": "UNVERIFIED",
        "filename": "test.properties",
        "lines": {
            "2": "password=changeit",
            "5": "password=changeit"
        },
        "secrets": "changeit",
        "types": [
            "Secret Keyword"
        ]
    },
    {
        "category": "VERIFIED_TRUE",
        "filename": "test.properties",
        "lines": {
            "3": "password=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
            "4": "test=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        },
        "secrets": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
        "types": [
            "JSON Web Token",
            "Secret Keyword"
        ]
    }
]
```

Or include only the false positives with `--only-false`:

```bash
$ detect-secrets audit --report --only-false .secret.baseline
[
    {
        "category": "VERIFIED_FALSE",
        "filename": "test.properties",
        "lines": {
            "7": "password=faketest"
        },
        "secrets": "faketest",
        "types": [
            "Secret Keyword"
        ]
    }
]
```
