# Contributing

Thanks for your interest in helping to grow this repository, and make it better
for developers everywhere! This document serves as a guide to help you quickly
gain familarity with the repository, and start your development environment so
that you can quickly hit the ground running.

## 1. Learn the Overall Layout of the Code

Be sure to read through the [overview of `detect-secrets`' design](/docs/design.md) before
starting to work on it! This will give you a better idea of the different components to the
system, and how they interact together to find secrets.

## 2. Building Your Development Environment

There are several ways to spin up your virtual environment:

**Casual Python Developers**:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
```

**Regular Python Developers:**

```bash
virtualenv --python=python3 venv
source venv/bin/activate
pip install -r requirements-dev.txt
```

> **Developer Note**: The main difference between this method and the former one (using Python's
  in-built virtual environment) is that Python's `venv` module pins the `pip` version. However,
  it doesn't matter too much if you're working on this repository alone, since `detect-secrets`
  doesn't ship with many dependency requirements.

or

```bash
tox -e venv
source venv/bin/activate
```

> **Developer Note**: The benefit of this is that `tox` sets up a common development environment
  for you. The downside is that you'll need to install `tox` first -- which if you already have,
  you wouldn't be reading this section :)


Whichever way you choose, you can check to see whether you're successful by executing:

```bash
python -m detect_secrets --version
```

## 3. Run tests

Tests should succeed on master. Any code additions you contribute will also need testing
so it's good to run tests first to make sure you have a working copy. Don't worry -- the tests
don't take long!

```bash
$ time python -m pytest tests
...
real    0m10.113s
user    0m6.848s
sys     0m2.486s
```

### Running the Entire Test Suite

You can run the test suite in the interpreter of your choice (in this example, `py36`) by doing:

```bash
tox -e py36
```

This will also run the code through our series of coverage tests, `mypy` rules and other linting
checks to enforce a consistent coding style.

For a list of supported interpreters, check out `envlist` in `tox.ini`.

If you wanted to run **all** interpreters (might take a while), you can also just run:

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
  pytest tests/core/baseline_test.py::TestCreate
  ```

- Running a single test function, inside test class

  ```bash
  pytest tests/core/baseline_test.py::TestCreate::test_basic_usage
  ```

- Running a single root level test function

  ```bash
  pytest tests/plugins/baseline_test.py::test_upgrade_succeeds
  ```

Generally speaking, we use test classes to group a series of related test cases together (e.g.
`TestCreate` tests the `detect_secrets.core.baseline.create` functionality), but root test
functions otherwise. If you're writing tests for your plugins, you should probably just use
root test functions.

## 4. Make Your Change

Want to contribute a new plugin? Check out more details here:
[Writing Your Own Plugin](/docs/plugins.md#Writing%20Your%20Own%20Plugin)

What about contributing better false positive filters? Check out more details here:
[Writing Your Own Filter](/docs/filters.md#Writing%20Your%20Own%20Filter)

## 5. Deploying Changes

Check out [more detailed upgrade instructions here](/docs/upgrades.md), and how to write
backwards-compatible changes using the built-in upgrade infrastructure.
