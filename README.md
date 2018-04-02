# detect-secrets

## About

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
accepting that there may *currently* be secrets hiding in your large repository,
but preventing this issue from getting any larger, without dealing with the
potentially gargantuous effort of moving existing secrets away.

It does this by running periodic diff outputs against heuristically crafted
regex statements, to identify whether any *new* secret has been committed. This
way, it avoids the overhead of digging through all git history, as well as the
need to scan the entire repository every time.

## Example Usage

### Setting Up a Baseline

```
$ detect-secrets --scan > .secrets.baseline
```

### Pre-commit Hook

```
$ cat .pre-commit-config.yaml
-   repo: git@github.com:yelp/detect-secrets.git
    sha: v0.6.3
    hooks:
    -   id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
        exclude: .*/tests/.*
```

## Installation

There are three components that you can setup, depending on your purposes.
While all three are independent, you should pair the Secrets Baseline with
either the client-side pre-commit hook, or the server-side secret scanner.

1. **Client-side Pre-Commit Hook**, that alerts developers when they attempt
   to enter a secret in the code base.

2. **Server-side Secret Scanning**, to periodically scan tracked repositories,
   and make sure developers didn't accidentally skip the pre-commit check.

3. **Secrets Baseline**, to whitelist pre-existing secrets in the repository,
   so that they won't be continuously caught through scan iterations.

### Client-side Pre-commit Hook

See [pre-commit](https://github.com/pre-commit/pre-commit) for instructions
to install the pre-commit framework. The example usage above has a sample
installation configuration, with a whitelisted secrets baseline.

Hooks available:

- `detect-secrets`: This hook detects and prevents high entropy strings from
  entering the codebase.

### Server-side Secret Scanning

There are several steps to setting up your server, to allow for customizability
dependent on the requirements of your existing system.

1. Installing the Server Tool
2. Setting up Default Settings (**optional**)
3. Specifying Tracked Repositories
4. Hooking Up an Alerting System
5. Installing Crontabs

#### 1. Installing the Server Tool

```
$ pip install detect-secrets
```

#### 2. Setting Up Default Settings

The following keys are accepted in your config file:

```
config.yaml
  |- default        # These are default values to use for each tracked repo.
```

The following attributes are supported under the `default` namespace, and set
default settings for all repositories scanned with the `detect-secrets-server`
tool.

All attributes are **optional**, and can be overriden in `repos.yaml`.

| attribute      | description
| -------------- | -----------
| base\_tmp\_dir | Local path used for cloning repositories, and storing tracked metadata.
| baseline       | Filename to parse the detect-secrets baseline from.
| exclude\_regex | Files to ignore, when scanning files for secrets.
| plugins        | List of plugins, with their respective settings. Currently, these take precedence over values set via command line.

See the sample `config.yaml.sample` for an example.

#### 3. Specifying Tracked Repositories

All tracked repositories need to be defined in `repos.yaml`.
See `repos.yaml.sample` for an example.

The following attributes are supported:

| attribute       | description
| --------------- | -----------
| repo            | Where to `git clone` the repo from (**required**)
| is\_local\_repo | True or False depending on if the repo is already on the filesystem (**required**)
| sha             | The commit hash to start scanning from (**required**)
| baseline        | The filename to parse the detect-secrets baseline from
| cron            | [crontab syntax](https://crontab.guru/) of how often to run a scan for this repo
| plugins         | List of plugins, with their respective settings. This takes precedence over both `config.yaml` settings, and command line arguments.

#### 4. Hooking Up an Alerting System

Currently, we only support [PySensu
alerting](http://pysensu-yelp.readthedocs.io/en/latest/#pysensu_yelp.send_event),
so check out those docs on configuring your Sensu alerts.

See the sample `.pysensu.config.yaml.sample` for an example, but be sure to
name your file `.pysensu.config.yaml`.

#### 5. Installing Crontabs

```
echo -e "$(crontab -l)\n\n$(detect-secrets-server --initialize)" | crontab -
```

### Secrets Baseline

```
$ pip install detect-secrets
```

Remember to initialize your baseline with the same sensitivity configurations
as your pre-commit hook, and server-side secret scanner!

#### Inline Whitelisting

Another way of whitelisting secrets is through the inline comment
`# pragma: whitelist secret`.

For example:

```
API_KEY = "blah-blah-but-actually-not-secret" # pragma: whitelist secret

def main():
    print('hello world')

if __name__ == '__main__'
    main()
```

This may be a convenient way for you to whitelist secrets, without having to
regenerate the entire baseline again. Furthermore, this makes the whitelisted
secrets easily searchable, auditable, and maintainable.

## Current Supported Plugins

The current heuristic searches we implement out of the box include:

* **Base64HighEntropyString**: checks for all strings matching the Base64
  character set, and alerts if their Shannon entropy is above a certain limit.

* **HexHighEntropyString**: checks for all strings matching the Hex character
  set, and alerts if their Shannon entropy is above a certain limit.

* **PrivateKeyDetector**: checks to see if any private keys are committed.

See [detect_secrets/
plugins](https://github.com/Yelp/detect-secrets/tree/master/detect_secrets/plugins)
for more details.

## A Few Caveats

This is not meant to be a sure-fire solution to prevent secrets from entering
the codebase. Only proper developer education can truly do that. This pre-commit
hook merely implements several heuristics to try and prevent obvious cases of
committing secrets.

### Things that won't be prevented

* Multi-line secrets.
* Default passwords (eg. `password = "password"`)

### Sensitivity Configuration

One method that this package uses to find secrets is by searching for high
entropy strings in the codebase. This is calculated through the [Shannon entropy
formula](http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html).
If the entroy of a given string exceeds the preset amount, the string will be
rejected as a potential secret.

This preset amount can be adjusted in several ways:

* Specifying it within the config file, for server scanning.
* Specifying it with command line flags (eg. `--base64-limit`)

Lowering these limits will identify more potential secrets, but also create
more false positives. Adjust these limits to suit your needs.
