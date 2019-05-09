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

3. Register your plugin

   Once your plugin is written and tested, you need to register it so that
   it can be disabled if other users don't need it. Be sure to add it to
   `detect_secrets.core.usage.PluginOptions` as a new option for users to
   use.

   Check out the following PRs for examples:
     - https://github.com/Yelp/detect-secrets/pull/74/files
     - https://github.com/Yelp/detect-secrets/pull/157/files

4. Update documentation

   Be sure to add your changes to the `README.md` and `CHANGELOG.md` so that
   it will be easier for maintainers to bump the version and for other
   downstream consumers to get the latest information about plugins available.

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
