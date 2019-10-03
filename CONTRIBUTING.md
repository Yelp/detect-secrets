# Contributing

Thanks for your interest in helping to grow this repository, and make it better
for developers everywhere! This document serves as a guide to help you quickly
gain familarity with the repository, and start your development environment so
that you can quickly hit the ground running.

## Layout

```
/detect_secrets               # This is where the main code lives
    /core                     # Powers the detect-secrets engine
    /plugins                  # All plugins live here, modularized.
        /common               # Common logic shared between plugins
    main.py                   # Entrypoint for console use
    pre_commit_hook.py        # Entrypoint for pre-commit hook

/test_data                    # Sample files used for testing purposes
/testing                      # Common logic used in test cases
/tests                        # Mirrors detect_secrets layout for all tests
```

## Building Your Development Environment

There are several ways to spin up your virtual environment:

```bash
virtualenv --python=python3 venv
source venv/bin/activate
pip install -r requirements-dev.txt
```

or

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
```

or

```bash
tox -e venv
source venv/bin/activate
```

Whichever way you choose, you can check to see whether you're successful by
executing:

```bash
PYTHONPATH=`pwd` python detect_secrets/main.py --version
```

## Writing a Plugin

There are many examples of existing plugins to reference, under
`detect_secrets/plugins`. However, this is the overall workflow:

1. Write your tests

   Before you write your plugin, you should **know what it intends to do**:
   what it should catch, and arguably more importantly, what it should
   avoid. Formalize these examples in tests!

   For a basic example, see `tests/plugins/basic_auth_test.py`.

2. Write your plugin

   All plugins MUST inherit from `detect_secrets.plugins.base.BasePlugin`.
   See that class' docstrings for more detailed information.

   Depending on the complexity of your plugin, you may be able to inherit
   from `detect_secrets.plugins.base.RegexBasedDetector` instead. This is
   useful if you want to merely customize a new regex rule. Check out
   `detect_secrets/plugins/basic_auth.py` for a good example of this.

   Be sure to write comments about **why** your particular regex was crafted
   as it is!

3. Update documentation

   Be sure to add your changes to the `README.md` and `CHANGELOG.md` so that
   it will be easier for maintainers to bump the version and for other
   downstream consumers to get the latest information about plugins available.

### Tips

- There should be a total of three modified files in a minimal new plugin: the
  plugin file, it's corresponding test, and an updated README.
- If your plugin uses customizable options (e.g. entropy limit in `HighEntropyStrings`)
  be sure to add default options to the plugin's `default_options`.

## Running Tests

### Running the Entire Test Suite

You can run the test suite in the interpreter of your choice (in this example,
`py35`) by doing:

```bash
tox -e py35
```

For a list of supported interpreters, check out `envlist` in `tox.ini`.

If you wanted to run **all** interpreters (might take a while), you can also
just run:

```bash
make test
```

### Running a Specific Test

With `pytest`, you can specify tests you want to run in multiple granularity
levels. Here are a couple of examples:

- Running all tests related to `core/baseline.py`

  ```bash
  pytest tests/core/baseline_test.py
  ```

- Running a single test class

  ```bash
  pytest tests/core/baseline_test.py::TestInitializeBaseline
  ```

- Running a single test function, inside test class

  ```bash
  pytest tests/core/baseline_test.py::TestInitializeBaseline::test_basic_usage
  ```

- Running a single root level test function

  ```bash
  pytest tests/plugins/base_test.py::test_fails_if_no_secret_type_defined
  ```

## Technical Details

### PotentialSecret

This lives at the very heart of the engine, and represents a line being flagged
for its potential to be a secret.

Since the detect-secrets engine is heuristics-based, it requires a human to read
its output at some point to determine false/true positives. Therefore, its
representation is tailored to support **high readability**. Its attributes
represent values that you would want to know (and keep track of) for
each potential secret, including:

1. What is it?
2. How was it found?
3. Where is it found?
4. Is it a true/false positive?

We can see that the JSON dump clearly shows this.

```
{
    "type": "Base64 High Entropy String",
    "filename": "test_data/config.yaml",
    "line_number": 5,
    "hashed_secret": "bc9160bc0ff062e1b2d21d2e59f6ebaba104f051",
    "is_secret": false
}
```

However, since it is designed for easy reading, we didn't want the baseline to
be the single file that contained all the secrets in a given repository.
Therefore, we mask the secret by hashing it with three core attributes:

1. The actual secret
2. The filepath where it was found
3. How the engine determined it was a secret

Any potential secret that has **all three values the same is equal**.

This means that the engine will flag the following cases as separate occurrences
to investigate:

* Same secret value, but present in different files
* Same secret value, caught by multiple plugins

Furthermore, this will **not** flag on every single usage of a given secret in a
given file, to minimize noise.

**Important Note:** The line number does not play a part in the identification
of a potential secret because code is expected to move around through continuous
iteration. However, through the `audit` tool, these line numbers are leveraged
to quickly identify the secret that was identified by a given plugin.

### SecretsCollection

A collection of `PotentialSecrets` are stored in a `SecretsCollection`. This
contains a list of all the secrets in a given repository, as well as any other
details needed to recreate it.

A formatted dump of a `SecretsCollection` is used as the baseline file.

In this way, the overall baseline logic is simple:

1. Scan the repository to create a collection of known secrets.
2. Check every new secret against this collection of known secrets.
3. If you previously didn't know about it, alert off it.

With this in mind, this class exposes three types of methods:

##### 1. Creating

We need to create a `SecretsCollection` object from a formatted baseline output,
so that we can compare new secrets against it. This means that the baseline
**must** include all information needed to initialize a `SecretsCollection`,
such as:

* Secrets found,
* Files to exclude,
* Plugin configurations,
* Version of detect-secrets used

##### 2. Adding

Once we have a collection of secrets, we can add secrets to it via various
methods of scanning strings. The various methods of scanning strings (e.g.
`scan_file`, `scan_diff`) should handle iterating through all plugins, and
adding results found to the collection.

##### 3. Outputting

We need to be able to create a baseline from a SecretsCollection, so that it
can be used for future comparisons. In the same spirit as the `PotentialSecret`
object, it is designed for **high readability**, and may contain other metadata
that aids human analysis of the generated output (e.g. `generated_at` time).
