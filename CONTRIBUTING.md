## Contributing

[fork]: /fork
[pr]: /compare

Hi there! We're thrilled that you'd like to contribute to this project. Your help is essential for keeping it great.

We are looking into contributing back the changes to the upstream project. Try not to include anything we want to keep private. If it does include something we want to keep private please indicate it in the PR. The details will be figured out how we are going to contribute back will come later.

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

## Changes we are looking for

We are looking for all sorts of changes. The changes will be broken down into 2 pieces:

1. Changes to the operations/flow of the tool. These are changes don't affect what secrets are found, but affect how the tool is used.
1. Changes to the secrets detection logic. This changes which secrets are going to be detected.

Which type to change is up to you to decide. If you are passionate about detecting secrets, then work on the logic. If you passionate about the UX or how to tool is used, then make a change to the operation/flow aspect of the tool.

## Issues and PRs

If you have suggestions for how this project could be improved, or want to report a bug, open an issue! We'd love all and any contributions. If you have questions, too, we'd love to hear them.

We'd also love PRs. If you're thinking of a large PR, we advise opening up an issue first to talk about it, though! Look at the links below if you're not sure how to open a PR.

## Submitting a pull request

1. [Fork][fork] and clone the repository.
1. Configure and install the dependencies as described in the [README.md](/README.md).
1. Make sure the tests pass on your machine as described in the [README.md](/README.md).
1. Create a new branch: `git checkout -b my-branch-name`.
1. Make your change, add tests, and make sure the tests still pass.
1. Push to your fork and [submit a pull request][pr].
1. Pat your self on the back and wait for your pull request to be reviewed and merged.

Here are a few things you can do that will increase the likelihood of your pull request being accepted:

-   Write and update tests.
-   Keep your changes as focused as possible. If there are multiple changes you would like to make that are not dependent upon each other, consider submitting them as separate pull requests.
-   Write a [good commit message](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html).

Work in Progress pull requests are also welcome to get feedback early on, or if there is something blocked you.

## Resources

-   [How to Contribute to Open Source](https://opensource.guide/how-to-contribute/)
-   [Using Pull Requests](https://help.github.com/articles/about-pull-requests/)
-   [GitHub Help](https://help.github.com)
-   [RegHex GitHub Project](https://github.com/l4yton/RegHex)

## Process for Adding a New Secret Detector to detect-secrets

There are two key steps for developing a new secret detector: secret identification and secret verification.
It is often easier to review contributions if these two steps are submitted as separate PRs, although this is not mandatory.
The processes for each of these two steps are outlined below.

### Secret Identification

-   Develop an understanding of all the secret types for a given service. A service may have combinations of basic-auth, IAM auth, tokens, keys, passwords, and / or other proprietary authentication methods.
-   Identify any specification documents from the service provider for the use & format of the secret types to be captured.
-   Develop an understanding of the API / service call uses.
    -   Is it purely RESTful, or are there prevalent SDKs which should be accounted for and detected?
-   Search / identify examples of the signature and use cases in github.ibm.com or create your own.
    -   Iterate until you have sufficient representation of the different ways in which the secret may be used.
-   Using the other detectors under `detect-secrets/plugins` as examples, create a new Python file under that path. The file should contain a new detector class which inherits from `RegexBasedDetector`.
-   Write one or more regexes to match and capture secrets when found within the use cases identified above. Assign a list of regexes to the `denylist` variable. We have created helper functions to make this easier, which may be seen in the existing detectors.
-   If multiple factors exist, identify a primary factor to capture with the `denylist` regexes. Secondary factors will be captured as part of the verification process below.
-   Create test cases to ensure that example secrets matching the (primary factor's) secret signature will be caught. Use the test files under `tests/plugins` as examples.

### Secret Verification

-   Identify a service endpoint (API call or SDK) which can be used to check the validity of a secret.
    -   In complex cases (where the service is hosted internally), it's often helpful to identify an IBM SME who can help navigate the API / SDK spec of the service for verification purposes. [w3 ProductPages](https://productpages.w3ibm.mybluemix.net/ProductPages/index.html) is a good resource to help identify an SME.
    -   Note: if there are _many_ signature hits, it may create a stressful load on the verification endpoint, so a key design point is to minimize false positive cases.
-   Using the existing plugins in `detect_secrets/plugins` as examples, add the `verify()` function to your detector. The `verify` function should validate a found secret with the service endpoint and determine whether it is active or not, returning either `VerifiedResult.VERIFIED_TRUE` or `VerifiedResult.VERIFIED_FALSE`. `verify()` may also return `VerifiedResult.UNVERIFIED` if verification cannot be completed due to issues like endpoint availability, lack of expected data elements, etc.
-   If multiple factors must be found to verify the secret, write an additional helper function to scan the context lines surrounding the primary factor. One or more additional regexes may be required. Context lines are passed to the `verify()` function as `content`. The number of context lines pulled from above and below the primary factor is defined in `plugins/base.py` as the global variable `LINES_OF_CONTEXT`.
-   Using the existing tests in `tests/plugins` as examples, create test cases for positive and negative verification results, considering required factors & return codes. Note that you should mock responses from the service endpoint to avoid actually calling it during tests.

## Building Your Development Environment

First, set up `pyenv`:

1. `brew install pyenv`
1. install the latest version of python with `pyenv install <version number>`
1. set the global version of python with `pyenv global <version number>`
1. To ensure the python installation controlled by `pyenv` is being used, you may need to add the following to your `.bashrc` (or equivalent):
    ```sh
    export PYENV_ROOT="$HOME/.pyenv"
    export PATH="$PYENV_ROOT/shims:$PATH"
    export PATH="$PYENV_ROOT/bin:$PATH"
    ```

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

Note that without `PYTHONPATH` set, Python will not be able to resolve imports
within this repo. Particularly if you have the `detect-secrets` package
installed in your environment, Python may resolve module imports from the
installed `detect-secrets` package instead of from within the repo where you're
developing. To avoid this, ensure `PYTHONPATH` is set in your developer
environment and includes the path to the detect-secrets repo.

## Debugging with VSCode

To execute the code locally with VSCode's debugger enabled, one option is to create a file at the root of the repository and then invoke the `main` function:

```python
# your_custom_main.py
import detect_secrets.main

print('starting')
# provide cli args as an array here
detect_secrets.main.main(['audit', '.secrets.baseline'])
```

Create the following launch settings and replace `your_custom_main.py` with the appropriate values:

```jsonc
{
    // Use IntelliSense to learn about possible attributes.
    // Hover to view descriptions of existing attributes.
    // For more information, visit: https://go.microsoft.com/fwlink/?linkid=830387
    // ${workspaceFolder} is a built-in VSCode environment variable and will automatically refer to the location of your codebase
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: Current File",
            "type": "python",
            "request": "launch",
            "program": "${workspaceFolder}/your_custom_main.py",
            "console": "integratedTerminal",
            "env": {
                "PYTHONPATH": "${workspaceFolder}"
            }
            // if you want to test the `audit` function against a different codebase,
            // uncomment the following line and provide the path to the codebase below:
            // "cwd": "directory/you/want/to/run/detect/secrets/against"
        }
    ]
}
```

Then start the debugger from your root-level main file.

## Running Tests

## Testing Dependencies

This project is written in Python. Here are the dependencies needed to run the tests:

-   `python` The version can be installed using an utility like pyenv ( instructions bellow ) or your os package manager
    -   `3.5`
    -   `3.6`
    -   `3.7`
    -   `3.8`
    -   `3.9`
-   `tox` installed via pip or your os package manager
-   `make`
-   `pre-commit`
    -   `pip install pre-commit`
    -   `pre-commit install`

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

If you run into dependency issues with the `cryptography` library, you may need to specify where `openssl` lives on your machine by adding the following to your `.bashrc` or equivalent:

```sh
# if you used brew to install openssl, your paths will likely be:
export LDFLAGS="-L/usr/local/opt/openssl/lib"
export CPPFLAGS="-I/usr/local/opt/openssl/include"
```

### Running a Specific Test

With `pytest`, you can specify tests you want to run in multiple granularity
levels. Here are a couple of examples:

-   Running all tests related to `core/baseline.py`

    ```bash
    pytest tests/core/baseline_test.py
    ```

-   Running a single test class

    ```bash
    pytest tests/core/baseline_test.py::TestInitializeBaseline
    ```

-   Running a single test function, inside test class

    ```bash
    pytest tests/core/baseline_test.py::TestInitializeBaseline::test_basic_usage
    ```

-   Running a single root level test function

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
    "hashed_secret": "[SECRET_HASH_HERE]",
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

-   Same secret value, but present in different files
-   Same secret value, caught by multiple plugins

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

-   Secrets found,
-   Files to exclude,
-   Plugin configurations,
-   Version of detect-secrets used

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
