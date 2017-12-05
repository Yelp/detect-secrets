# detect_secrets

## Description

This is loosely based off [truffleHog](https://github.com/dxa4481/truffleHog/blob/master/truffleHog/truffleHog.py)'s secret scanner. However, instead of analyzing the entire git-history for secrets that have **ever** entered the repository, we wanted to perform preventative checks to make sure that no **additional** secrets will be added to the codebase.

This is perfect for a backwards compatible solution, where you accept that there may **currently** be secrets hiding in your large repository, and you want to prevent new ones from entering without first dealing with the potentially gargantuous effort to move existing secrets away.

We deal with this in two steps:

1. Use a client-side pre-commit hook, to alert developers when they attempt to enter a secret in the code base.
2. Set up a server-side cron job to periodically scan tracked repositories, to make sure that developers didn't accidentally skip the pre-commit check.

## Installation

There are three components that you can setup, depending on your purposes.

### Pre-Commit Hook

See [pre-commit](https://github.com/pre-commit/pre-commit) for instructions to install the pre-commit framework.

Hooks available:

- `detect-secrets`: This hook detects and prevents high entropy strings from entering the codebase.

### Console Use / Server Use

`pip install detect-secrets`

## Configuration

### Installing a baseline

#### Step 1: Initialize your baseline.

```
$ detect-secrets --initialize --exclude='^(\.git|venv)' > .secrets.baseline
```

#### Use your baseline in your pre-commit hook

```
- repo: <this repo>
  hooks:
    - id: detect-secrets
      args: ['--baseline', '.secrets.baseline']
```

Remember to initialize your baseline with the same sensitivity configurations as your pre-commit hook!

### Sensitivity Configuration

This module works by searching for high entropy strings in the codebase, and [calculating their Shannon entropy](http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html). If the entropy of a given string exceeds the preset amount, the string will be rejected as a potential secret.

The sensitivity of this pre-commit hook can be adjusted with command-line flags (eg. `--base64_limit` and `--hex_limit`). Lowering these limits will identify more potential secrets, but also create more false positives. Adjust these limits to suit your needs.

If you want a lower limit, but also want to whitelist specific strings from being detected, you can add the comment `# pragma: whitelist secret` to the line of code.

For example:

```
API_KEY = "blah-blah-but-actually-not-secret" # pragma: whitelist secret

def main():
    print('hello world')

if __name__ == '__main__'
	main()
```

This is the preferred way of whitelisting high entropy strings (rather than adding it to the baseline file), because it is easily searchable, auditable, and maintainable.

### Setting up your server

#### Step 1: Configure your config.yaml

The following keys are accepted in your config file:

```
config.yaml
  |- default		# These are default values to use for each tracked repo.
  |- tracked		# This is a list of tracked repos' details.
```

Each tracked repository can have the following attributes:

| attribute     | description
| --------------| -----------
| repo          | where to `git clone` the repo from (**required**)
| is_local_repo | True or False depending on if the repo is already on the filesystem (**required**)
| sha           | the commit hash to start scanning from (**required**)
| cron          | [crontab syntax](https://crontab.guru/) of how often to run a scan for this repo
| plugins       | list of plugins, with their respective settings
| baseline      | the filename to parse the detect-secrets baseline from

See the sample `config.yaml.sample` for an example.

#### Step 2: Configure your .pysensu.config.yaml

See (pysensu-yelp)[http://pysensu-yelp.readthedocs.io/en/latest/#pysensu_yelp.send_event] for instructions on configuring your Sensu events.

See the sample `.pysensu.config.yaml.sample` for an example, but be sure to name your file `.pysensu.config.yaml`.

#### Step 3: Setup your cron jobs

```
echo -e "$(crontab -l)\n\n$(detect-secrets-server --initialize)" | crontab -
```

## Use Cases

### Fresh Respository

**Scenario**: You are starting a brand new repo, so you **know** you haven't committed any secrets to the codebase yet. Moving forward, you want to make sure you don't do so.

**Solution**: Great! Just [install the pre-commit hook](TODO:Link) for preventative measures.

### Existing Repository

**Scenario**: You have an existing repo that may or may not have secrets added to it before. You want to prevent further secrets from being committed, yet it's too much work to migrate all currently existing secrets in the codebase out.

**Solution**:

1. Create a baseline of existing secrets, so that the pre-commit hook will only detect the new secrets added.
2. [Install the pre-commit hook](TODO:Link) for preventative measures.

## A Few Caveats

This is not meant to be a sure-fire solution to prevent secrets from entering the codebase. Only proper developer education can truly do that. This pre-commit hook merely implements several heuristics to try and prevent obvious cases of committing secrets.

### Things that won't be prevented

* Multi-line secrets.
* Default passwords (eg. `password = "password"`)
