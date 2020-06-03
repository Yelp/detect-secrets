# Whitewater Detect Secrets

## About

The purpose of the project is to **detecting secrets** within a code base. This is a fork of [detect-secrets](https://github.com/Yelp/detect-secrets) from yelp. This include more detection, some of which are unique for IBM. Additional features to help integrate with services IBM uses.

`detect-secrets` is an aptly named module for (surprise, surprise) **detecting
secrets** within a code base.

However, unlike other similar packages that solely focus on finding secrets,
this package is designed with the enterprise client in mind: providing a
**backwards compatible**, systematic means of:

1. Preventing new secrets from entering the code base,
2. Detecting if such preventions are explicitly bypassed, and
3. Providing a checklist of secrets to roll, and migrate off to a more secure
   storage.

This way, you create a
[separation of concern](https://en.wikipedia.org/wiki/Separation_of_concerns):
accepting that there may *currently* be secrets hiding in your large repository
(this is what we refer to as a _baseline_),
but preventing this issue from getting any larger, without dealing with the
potentially gargantuous effort of moving existing secrets away.

It does this by running periodic diff outputs against heuristically crafted
regex statements, to identify whether any *new* secret has been committed. This
way, it avoids the overhead of digging through all git history, as well as the
need to scan the entire repository every time.

For a look at recent changes, please see the
[changelog](/CHANGELOG.md).

## User Guide

If you are looking for information on how to use this project as an end user please refer to the [user guide](https://w3.ibm.com/w3publisher/detect-secrets).

## Contribution

Please read the [CONTRIBUTING.md](/CONTRIBUTING.md). Bellow is information on how setup the testing environment, and run the tests.

## Testing

To run the tests you need install the dependencies described bellow.

You need to run the setup once or after you do a `make clean`. To run the setup run the following command:

```
make setup
```

To run the tests run:

```
make test
```

If you want to clean you environment, if you have a bad setup or tests, just run:

```
make clean
```

## Testing Dependencies

This project is written in Python. Here are the dependencies needed to run the tests:
- `python` The version can be installed using an utility like pyenv ( instructions bellow ) or your os package manager
    - `2.7`
    - `3.5`
    - `3.6`
    - `pypy`
- `tox` installed via pip or your os package manager
- `make`
- `pre-commit`
    - `pip install pre-commit`
    - `pre-commit install`

#### Installing via pyenv

1. Install [pyenv](https://github.com/pyenv/pyenv) in your environment. **Note:** you need to add the environment to you `.bashrc`. You will most likely run into the common build problems listed [here](https://github.com/pyenv/pyenv/wiki/Common-build-problems).
1. Install the environment listed above
1. Set the environment as global using the `pyenv global $VERSION` command
1. Install tox `pip install tox`


#### Running test in a docker image

If you don't want to figure out how to install it locally or don't want to spend the time you can use the development docker image. Install `docker` and `docker-compose`. Then run:

```
docker-compose build test && docker-compose run --rm test
```

## Plugins

Each of the secret checks are developed as plugins in the [detect_secrets/plugins](/detect_secrets/plugins) directory. Each plugin represents a single test or a group of tests.

Refer to the plugin directory above for the list of supported secret detectors.

## IBM versioning and rebase guide

- [update.md](./update.md)
