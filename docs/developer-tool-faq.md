# FAQ (Detect Secrets Suite - Developer tool)

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

-   [pip setup](#pip-setup)
    -   [I’m getting a `Could not install packages due to an Environment Error: [Errno 13] Permission denied: ` error when installing the `detect-secrets` pip package. What should I do?](#im-getting-a-could-not-install-packages-due-to-an-environment-error-errno-13-permission-denied--error-when-installing-the-detect-secrets-pip-package-what-should-i-do)
    -   [I cannot find the `detect-secrets` binary after installation](#i-cannot-find-the-detect-secrets-binary-after-installation)
    -   [How do I upgrade `detect-secrets` to a newer version?](#how-do-i-upgrade-detect-secrets-to-a-newer-version)
        -   [Upgrade for user mode](#upgrade-for-user-mode)
        -   [Upgrade for global mode - keep install to global mode](#upgrade-for-global-mode---keep-install-to-global-mode)
        -   [Upgrade for global mode - switch to user mode](#upgrade-for-global-mode---switch-to-user-mode)
    -   [How do I set up the pre-commit hook?](#how-do-i-set-up-the-pre-commit-hook)
    -   [How do I upgrade the `detect-secrets` pre-commit hook?](#how-do-i-upgrade-the-detect-secrets-pre-commit-hook)
-   [General usage](#general-usage)
    -   [Which python versions does detect-secrets support?](#which-python-versions-does-detect-secrets-support)
    -   [How do I generate a baseline file?](#how-do-i-generate-a-baseline-file)
    -   [How do I re-generate (update) my baseline file?](#how-do-i-re-generate-update-my-baseline-file)
    -   [How do I audit my baseline file?](#how-do-i-audit-my-baseline-file)
    -   [What to do after marking an potential secret as a valid secret?](#what-to-do-after-marking-an-potential-secret-as-a-valid-secret)
    -   [How can fixed entries be removed from my baseline file?](#how-can-fixed-entries-be-removed-from-my-baseline-file)
    -   [Will `detect-secrets` find tokens in git history?](#will-detect-secrets-find-tokens-in-git-history)
    -   [What kinds of tokens does detect-secrets find?](#what-kinds-of-tokens-does-detect-secrets-find)
    -   [Why is the Slack webhook considered a secret?](#why-is-the-slack-webhook-considered-a-secret)
    -   [Which plugins are used in the scan by default?](#which-plugins-are-used-in-the-scan-by-default)
    -   [How do I use fewer plugins when scanning?](#how-do-i-use-fewer-plugins-when-scanning)
    -   [`detect-secrets` generates too many false positives. What should I do?](#detect-secrets-generates-too-many-false-positives-what-should-i-do)
        -   [Exclude some files with the `—exclude-files` option.](#exclude-some-files-with-the-exclude-files-option)
        -   [Tune the threshold for the entropy based scanner](#tune-the-threshold-for-the-entropy-based-scanner)
        -   [Use fewer scanners](#use-fewer-scanners)
    -   [Why did `detect-secrets` not find some secrets in my code?](#why-did-detect-secrets-not-find-some-secrets-in-my-code)
        -   [Cause 1: Not using all plugins](#cause-1-not-using-all-plugins)
        -   [Cause 2: Verifiable token is verified as false](#cause-2-verifiable-token-is-verified-as-false)
        -   [Cause 3: The entropy threshold is too high for entropy based plugins](#cause-3-the-entropy-threshold-is-too-high-for-entropy-based-plugins)
        -   [Cause 4: Unsupported token type](#cause-4-unsupported-token-type)
    -   [Why is the `detect-secrets` pre-commit output messed up with multiple headings and footers?](#why-is-the-detect-secrets-pre-commit-output-messed-up-with-multiple-headings-and-footers)
    -   [How do I configure the `detect-secrets` pre-commit hook with the Node.js husky library?](#how-do-i-configure-the-detect-secrets-pre-commit-hook-with-the-nodejs-husky-library)
    -   [How do I use inline allowlisting?](#how-do-i-use-inline-allowlisting)
    -   [Why does my scan get stuck](#why-does-my-scan-get-stuck)
    -   [Can I use detect-secrets to detect secrets in an arbitrary file system/folder that is not a git repo?](#can-i-use-detect-secrets-to-detect-secrets-in-an-arbitrary-file-systemfolder-that-is-not-a-git-repo)
    -   [Why is detect-secrets not verifying my password on DB2 for zOS?](#why-is-detect-secrets-not-verifying-my-password-on-db2-for-zos)
        -   [Missing certificates (known limitation)](#missing-certificates-known-limitation)
-   [docker setup](#docker-setup)
    -   [How do I install the `detect-secrets` docker image?](#how-do-i-install-the-detect-secrets-docker-image)
        -   [Prerequisite](#prerequisite)
        -   [Setup steps](#setup-steps)
            -   [1. scan with docker image](#1-scan-with-docker-image)
            -   [2. audit the baseline file](#2-audit-the-baseline-file)
            -   [3. setup pre-commit hook](#3-setup-pre-commit-hook)
    -   [How do I run a scan with the docker image?](#how-do-i-run-a-scan-with-the-docker-image)
        -   [Windows Powershell and cmd](#windows-powershell-and-cmd)
        -   [Windows git bash](#windows-git-bash)
        -   [MacOS & Linux](#macos--linux)
    -   [How do I run an audit with the docker image?](#how-do-i-run-an-audit-with-the-docker-image)
        -   [Windows Powershell and cmd](#windows-powershell-and-cmd-1)
        -   [Windows git bash](#windows-git-bash-1)
        -   [MacOS & Linux](#macos--linux-1)
    -   [How do I setup a pre-commit hook with the docker image?](#how-do-i-setup-a-pre-commit-hook-with-the-docker-image)
    -   [How do I upgrade docker image in a pre-commit hook?](#how-do-i-upgrade-docker-image-in-a-pre-commit-hook)
    -   [Can I pull a specific version of docker image?](#can-i-pull-a-specific-version-of-docker-image)
    -   [How do I run `detect-secrets` commands with the docker image on different operating systems?](#how-do-i-run-detect-secrets-commands-with-the-docker-image-on-different-operating-systems)
        -   [Windows Powershell and cmd](#windows-powershell-and-cmd-2)
        -   [Windows git bash](#windows-git-bash-2)
        -   [MacOS & Linux](#macos--linux-2)
    -   [Powershell docker command is too long, do you have some shortcut for detect-secrets?](#powershell-docker-command-is-too-long-do-you-have-some-shortcut-for-detect-secrets)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## pip setup

### I’m getting a `Could not install packages due to an Environment Error: [Errno 13] Permission denied: ` error when installing the `detect-secrets` pip package. What should I do?

This is normally caused by `pip` trying to add the package to system folders which the current user does not have write permission to. You can try to add the `--user` option to `pip install` like below

```sh
pip install --user git+https://github.com/ibm/detect-secrets.git@master#egg=detect-secrets
```

If adding `--user` does not resolve the issue, there are some cases where back-level `pip` can cause a permissions issue. In this case, please upgrade `pip`:

```sh
pip install --user --upgrade pip
```

Then perform the `detect-secrets` install again.

### I cannot find the `detect-secrets` binary after installation

By default, the tool will be installed at `~/Library/Python/<python_version>/bin/detect-secrets` on Mac (similar directory on Linux). If you cannot find `detect-secrets`, you can add the installation bin directory to your PATH by running `export PATH=$PATH:~/Library/Python/<python_version>/bin`

### How do I upgrade `detect-secrets` to a newer version?

`detect-secrets` can be installed in either `user` mode or `global` mode. You can run the one-liner below to identify where `detect-secrets` is installed.

```sh
if pip list | grep detect-secrets > /dev/null ; then echo "Installed with global mode, no need to use '--user' during upgrade"; elif pip list --user | grep detect-secrets > /dev/null; then echo "Installed with user mode, use '--user' during upgrade"; else echo "Have not installed before, use '--user'"; fi
```

#### Upgrade for user mode

If detect-secrets was installed in user mode previously, keep using the `--user` parameter in the upgrade command below.

```sh
pip install --upgrade --user git+https://github.com/ibm/detect-secrets.git@master#egg=detect-secrets
```

If `detect-secrets` was installed in global mode previously, either keep the install to global mode or switch to user mode.

#### Upgrade for global mode - keep install to global mode

```sh
pip install --upgrade git+https://github.com/ibm/detect-secrets.git@master#egg=detect-secrets
```

#### Upgrade for global mode - switch to user mode

```sh
pip uninstall detect-secrets
pip install --upgrade --user git+https://github.com/ibm/detect-secrets.git@master#egg=detect-secrets
```

If you cannot find `detect-secrets` after upgrading, refer to [this](#i-cannot-find-the-detect-secrets-binary-after-installation) documentation to set up the path.

> Note: if you install `detect-secrets` as a pre-commit hook, you should also [upgrade it in the `pre-commit` framework](#how-do-i-upgrade-the-detect-secrets-pre-commit-hook).

### How do I set up the pre-commit hook?

The pre-commit hook will automatically scan your code for secrets and block local commits if potential secrets are found.

1. Install the pre-commit hook framework: `pip install pre-commit`.
2. Add this [.pre-commit-config.yaml](../user-config/.pre-commit-config.yaml) file to the root folder of your repo.
3. Install the pre-commit hook: `pre-commit install` (this step will need to be done each time you clone a new repo).
4. The pre-commit hook will now scan each commit for secrets, referencing the baseline file, and block commits with secrets. If the pre-commit hook catches more false positives, rerun the baseline audit and indicate which secrets are false positives.
5. Invite your teammates to install pre-commit in their local env to prevent leaks too.

### How do I upgrade the `detect-secrets` pre-commit hook?

> Note: `autoupdate` only scans for tags on the master branch. It does **not** support the dss branch right now. Before dss has been released to the master branch, please use a specific version tag such as `rev: 0.13.0+ibm.7.dss` in `.pre-commit-config.yaml` to get the latest dss version.

The `pre-commit` framework manages its own copy of the `detect-secrets` tool. To upgrade it you need to

```sh
cd <your_repo_have_pre_commit_configured>
pre-commit autoupdate
# The rev field for detect-secrets in .pre-commit-config.yaml will be updated
# if the newest tag on the master branch is different from the value in current rev field.
# You should commit and check in the updated file once it's been updated.
```

If the steps above do not work, you can also update `pre-commit` to a newer version, then clean up the `pre-commit` cache and auto-update again.

```sh
pip install --upgrade pre-commit -y
pre-commit clean
pre-commit gc
pre-commit autoupdate
```

## General usage

### Which python versions does detect-secrets support?

This tool supports Python 3.5 and above. Since Python 2 reached its end of life on January 1st, 2020, `detect-secrets` supported Python 2 until July 1st, 2020.

You can follow the guide [here](https://docs.python-guide.org/starting/installation/) to properly setup your Python 3 environment.

> Note: If you are using macOS, the default Python installation is version 2, please make sure you follow the guide above to properly install Python 3.

### How do I generate a baseline file?

```shell
detect-secrets scan --update <baseline>
```

### How do I re-generate (update) my baseline file?

```shell
detect-secrets scan --update <baseline_file> <optional --no-xxx-scan or --use-all-plugins to adjust scan plugin list>
```

### How do I audit my baseline file?

-   You can audit entries which do not have the `is_secret` field with `detect-secrets audit <baseline>`

### What to do after marking an potential secret as a valid secret?

See [audit documentation](audit.md#what-to-do-after-marking-an-potential-secret-as-a-valid-secret?).

### How can fixed entries be removed from my baseline file?

-   Running `detect-secrets scan --update <baseline_file>` will clean up old entries.
-   Once you have the pre-commit hook configured, if there are no new issues found, this hook will clean up old (remediated) entries from the baseline file. You can also manually trigger this process by running `detect-secrets-hook --baseline <baseline> <changed_file>`. If the pre-commit check fails, the baseline file will not be updated.

### Will `detect-secrets` find tokens in git history?

No, by default the `detect-secrets` CLI tool only scans the code in the current commit.

### What kinds of tokens does detect-secrets find?

Our developer tool uses the following plugins by default

> Note that all of the listed plugins are used by Detect Secrets, but only certain ones support verification (i.e. checking if the tokens are active)

Supports verification

-   AWS Key
-   Slack
-   Artifactory
-   Box
-   Cloudant
-   DB2
-   Github
-   IBM Cloud IAM
-   IBM COS HMAC
-   SoftLayer
-   Stripe
-   Mailchimp

Does not support verification

-   Private Key Detector
-   Basic Auth Detector
-   Base64 High Entropy String
-   Hex High Entropy String
-   Keyword Detector
-   JSON Web Token

If you wish, check out our plugins folder (`detect_secrets/plugins`) for more details about what we scan.

### Why is the Slack webhook considered a secret?

Based on the Slack doc below, incoming webhooks should be considered secrets <https://api.slack.com/messaging/webhooks>.

> Keep it secret, keep it safe. Your webhook URL contains a secret. Don't share it online, including via public version control repositories. Slack actively searches out and revokes leaked secrets.

### Which plugins are used in the scan by default?

-   All plugins will be used when not reading the config from an existing baseline.
-   When using the `--update <baseline>` option with the existing baseline, the tool will only use the plugins listed in the baseline. Use `--use-all-plugins` along with `--update <baseline>` to force the use of all plugins.

### How do I use fewer plugins when scanning?

You can use the `--use-all-plugins` and `--no-xxx-scan` options (replace `xxx` with plugin name, use `detect-secrets scan --help` to list out the options) to customize the plugin list. The added plugins will persist in the baseline file. If you use `-—update <baseline>` in `detect-secrets` or `--baseline <baseline>` in `detect-secrets-hook` to run a scan without additional options, the plugins used will be read from the baseline file.

Example: `detect-secrets scan --update .secrets.baseline --use-all-plugins`

### `detect-secrets` generates too many false positives. What should I do?

If the false positive hits are overwhelming, you can tune the tool in several ways (it's recommended to try this before turning off the check):

#### Exclude some files with the `—exclude-files` option.

Detect Secrets supports regex-based file and folder exclusions. The excludes file list will be recorded in the outputted baseline file. In future scans, if no `--exclude-files` option is provided, the existing exclude list in the baseline file will be respected. If a new exclude list is supplied through the command line, it will overwrite the existing exclude list in the baseline file.

```sh
detect-secrets scan --update .secrets.baseline --exclude-files '<folder_to_ignore>|<file_to_ignore>'
```
Example: `detect-secrets scan --update .secrets.baseline --exclude-files "package-lock.json"`

#### Tune the threshold for the entropy based scanner

-   Entropy based scanning can be tricky to tune. It depends on your project, so you may want to run a `detect-secrets` scan several times to strike the right balance between the number of legitimate secrets versus false positives.
-   There are two types of entropy based scans, hex and base64. Each of them has a different character set. You can use either `--base64-limit` or `--hex-limit` with a new limit.
-   All future scans need to use the same limit number in the command line, otherwise a default value will overwrite the setting in the baseline file. You can specify these options in `.pre-commit-config.yaml` to make your pre-commit hook always use same options.

```sh
detect-secrets scan --base64-limit <new_limit>
# or
detect-secrets scan --hex-limit <new_limit>
```

#### Use fewer scanners

-   The `--no-<scan_type>-scan` option can be used to exclude certain types of scanning. Use `detect-secrets scan —help` to view more options.
-   All future scans need to use the same no scan options in the command line, otherwise the default value will overwrite the setting in the baseline file. You can specify these options in `.pre-commit-config.yaml` to make your `pre-commit` hook always use same options.
-   By default, all plugins are used.
-   To disable all entropy based scanning, use the command below

```sh
detect-secrets scan --no-base64-string-scan --no-hex-string-scan
```

### Why did `detect-secrets` not find some secrets in my code?

There are several things that can cause this. Many of them are by design and intended to avoid false positives. These behaviors can be adjusted.

#### Cause 1: Not using all plugins

The Developer Tool uses all plugins by default. But if a baseline file is used (with `--update OLD_BASELINE_FILE` for scan, and `--baseline BASELINE` for the `pre-commit` hook), the scan will respect the plugin list in the baseline and only use the plugins specified in the baseline.

You can use the `--use-all-plugins` option to mandate a scan using all plugins. The `--use-all-plugins` option is available in both the scan and pre-commit hook.

#### Cause 2: Verifiable token is verified as false

The Developer Tool will verify [some verifiable token types](#what-kinds-of-tokens-does-detect-secrets-find) by default. This means that when a potential token is found, the tool will use the token to test against the target service.

-   If the verification result is true or unable to verify, the potential token will be kept in the scan result.
-   If the verification result is false, then the token will be left out of the scan result. This is intended to reduce false positives so only valid tokens will be reported.

You can turn off the verification behavior with the `--no-verify` flag. This option is available in both the scan and the pre-commit hook.

#### Cause 3: The entropy threshold is too high for entropy based plugins

Tuning the entropy to a lower value by following the [tune the threshold for entropy based scanner](#tune-the-threshold-for-entropy-based-scanner) documentation may result in more tokens being caught.

#### Cause 4: Unsupported token type

This can happen if the signature of one token type is not supported by the `detect-secrets` tool. You can contribute a new token type following the guide [here](../CONTRIBUTING.md#process-for-adding-a-new-secret-detector-to-detect-secrets).

### Why is the `detect-secrets` pre-commit output messed up with multiple headings and footers?

Below is what a usual pre-commit scan output looks like. The potential secrets warning heading is printed first, then followed by the found secret type and locations, then the possible mitigations footer.

```shell
Potential secrets about to be committed to git repo! Please rectify or
explicitly ignore with an inline `pragma: allowlist secret` comment.

Secret Type: DB2 Credentials
Location:    myfile/something.java:80

Possible mitigations:

  - For information about putting your secrets in a safer place,
    please ask in #security
  - Mark false positives with an inline `pragma: allowlist secret`
    comment
  - Commit with `--no-verify` if this is a one-time false positive

If a secret has already been committed, visit
https://help.github.com/articles/removing-sensitive-data-from-a-
repository
```

If you are seeing headings and footers printed multiple times, along with reporting of token locations injected between lines, then you are running into the issue described by this question.

The reason behind this is the pre-commit framework's default parallel execution optimization. pre-commit scans all files in the git staging area upon commit creation, or all files managed by git if the `--all-files` option is used. To speed up the scan, pre-commit will split all the files to be scanned into multiple groups, and fire up multiple threads to run the scan concurrently. The number of threads is up to the total number of CPU cores. Each individual thread will output the result without coordination which leads to the messed up output. This only happens when many files have been fed into pre-commit, such as when your commit contains a lot of changed files or you are using the `--all-files` option.

To avoid messed up output, you can add `require_serial: true` option to `pre-commit-config.yaml` like below. It will still output headings and footers multiple times, but each thread's output would be in sequence. Be careful though, using serial execution might increase the total scan time.

```yaml
- repo: local
  hooks:
      - id: <hook_id>
        # other hook config here...
        require_serial: true
```

### How do I configure the `detect-secrets` pre-commit hook with the Node.js husky library?

If you are using the [husky](https://github.com/typicode/husky) library to manage the pre-commit hook, you can use the snippet below in your `package.json` to properly invoke `detect-secrets-hook`. The main problem is that detect-secrets-hook is expecting a list of files in the git staging area. husky is not feeding the file list to the pre-commit hook line as a parameter. The following setting will manually generate the list of staged files.

```json
  "husky": {
    "hooks": {
      "pre-commit": "detect-secrets-hook --baseline .secrets.baseline $(git diff --cached --name-only)"
    }
  }
```

### How do I use inline allowlisting?

The tool supports the following inline allowlisting syntax.

> **Note: a space is needed between the original line content and the comment**

```bash
secret # pragma: allowlist secret
secret // pragma: allowlist secret
secret /* pragma: allowlist secret */
secret ' pragma: allowlist secret
secret -- pragma: allowlist secret
secret <!-- pragma: allowlist secret -->
secret <!-- # pragma: allowlist secret -->
```

### Why does my scan get stuck

There are most likely some big text files causing the scan to run very slowly. This gives the appearance that the scan is stuck. You can find these offending files and exclude them from scanning.

To find the offending file, run the scan with the `--verbose` option like below

```bash
detect-secrets --verbose scan <file_or_folder_to_scan>
```

The command above will emit which file is currently being scanned. Once you've identified the file, you can use `--exclude-files` option to skip the offending file(s).

### Can I use detect-secrets to detect secrets in an arbitrary file system/folder that is not a git repo?

Yes.

To scan arbitrary files

```bash
detect-secrets scan <file_1> <file_2>
```

To scan an arbitrary folder, use the `scan --all-files` option

```bash
 detect-secrets scan --all-files <folder_name>
```

### Why is detect-secrets not verifying my password on DB2 for zOS?

A known case when DB2 for zOS password has not been caught is that you are missing certificates (known limitation).

#### Missing certificates (known limitation)

If your DB2 server requires a keystore DB and a keystash file to connect, then `detect-secrets` won't test the connection to
verify the token. This is known limitation. You can still run the scan with `--no-verify` flag;
It will report on the potential password string, but won't verify it against remote DB2 server.

## docker setup

The `detect-secrets` tool can also be run as a docker container. It supports Windows 10, macOS and Linux environments.

### How do I install the `detect-secrets` docker image?

#### Prerequisite

You need to have Python and [install the pre-commit framework](https://pre-commit.com/#install). The docker image of `detect-secrets` saves you the effort of installing the detect-secret pip package, which would require a heavy weight compilation environment. Besides that, please also make sure you have [docker installed](https://docs.docker.com/install/).

1. python [installed](https://docs.python-guide.org/starting/installation/)
1. pre-commit framework [installed](https://pre-commit.com/#install)
1. docker [installed](https://docs.docker.com/install/)

#### Setup steps

##### 1. scan with docker image

See [How do I run a scan with the docker image?](#how-do-i-run-a-scan-with-the-docker-image)

##### 2. audit the baseline file

See [How do I run an audit with the docker image?](#how-do-i-run-an-audit-with-the-docker-image)

##### 3. setup pre-commit hook

See [How do I setup a pre-commit hook with the docker image?](#how-do-i-setup-a-pre-commit-hook-with-the-docker-image)

### How do I run a scan with the docker image?

#### Windows Powershell and cmd

> Note: You can also setup a Powershell script following [doc here](#powershell-docker-command-is-too-long-do-you-have-some-shortcut-for-detect-secrets) to avoid typing the long command.

```shell
# scan
# Mount to /code folder is important since it's the workdir for detect-secrets
docker run -it --rm -v c:/replace/with/your/folder/containing/git/repo:/code ibmcom/detect-secrets:latest scan

# generate or update baseline
#
# Note: please do NOT use "> .secrets.baseline" to generat new baseline on Windows platform as it will generate Linux line ending format from docker output.
docker run -it --rm -v c:/replace/with/your/folder/containing/git/repo:/code ibmcom/detect-secrets:latest scan --update .secrets.baseline
```

#### Windows git bash

```shell
# the leading / is important for git bash env
# do not wrap trailing command after docker image is also important
winpty docker run -it --rm -v /$(pwd):/code ibmcom/detect-secrets:latest scan

# generate or update baseline
winpty docker run -it --rm -v /$(pwd):/code ibmcom/detect-secrets:latest scan --update .secrets.baseline
```

#### MacOS & Linux

```shell
# scan
docker run -it --rm -v $(pwd):/code ibmcom/detect-secrets:latest scan

# generate or update baseline
docker run -it --rm -v $(pwd):/code ibmcom/detect-secrets:latest scan --update .secrets.baseline
```

### How do I run an audit with the docker image?

#### Windows Powershell and cmd

> Note: You can also setup a Powershell script following [doc here](#powershell-docker-command-is-too-long-do-you-have-some-shortcut-for-detect-secrets) to avoid typing the long command.

```shell
docker run -it --rm -v c:/replace/with/your/folder/containing/git/repo:/code ibmcom/detect-secrets:latest audit .secrets.baseline
```

#### Windows git bash

```shell
winpty docker run -it --rm -v /$(pwd):/code ibmcom/detect-secrets:latest audit .secrets.baseline
```

#### MacOS & Linux

```shell
docker run -it --rm -v $(pwd):/code ibmcom/detect-secrets:latest audit .secrets.baseline
```

### How do I setup a pre-commit hook with the docker image?

1. Add the following content to `.pre-commit-config.yaml`.

```shell
# .pre-commit-config.yaml
-   repo: local
    hooks:
    -   id: detect-secrets-docker
        name: detect-secrets-docker
        language: docker_image
        entry: ibmcom/detect-secrets-hook:latest --baseline .secrets.baseline
```

1. [Windows environment], run the following command to turn off the CRLF warning message

```shell
git config --global core.safecrlf false
```

1. Install the pre-commit hook to the git repo with `pre-commit install`

### How do I upgrade docker image in a pre-commit hook?

1. Identify the docker image tag for `ibmcom/detect-secrets-hook` in your `.pre-commit-config.yaml` file. For example, the default is `latest`.
1. If you are using a latest tag such as `latest`.
    1. In a terminal, run `docker pull ibmcom/detect-secrets-hook:latest` to get the latest image.
1. If you are using a specific version tag, such as `0.13.1+ibm.37.dss`
    1. Update the `.pre-commit-config.yaml` to use a newer version tag.

### Can I pull a specific version of docker image?

Yes, any tag listed [in docker hub for image ibmcom/detect-secrets](https://hub.docker.com/repository/docker/ibmcom/detect-secrets) can be used. You can use the same approach to find tags for `ibmcom/detect-secrets-hook`.

The latest version for `detect-secrets` suite is `latest`.

> Note: due to docker tagging restriction, plus sign (`+`) is not allowed. The `+` in any tag on Github repo would be replaced by `.`. For example, tag `0.13.0+ibm.8.dss` would have docker image label `0.13.0.ibm.8.dss`

### How do I run `detect-secrets` commands with the docker image on different operating systems?

To run other `detect-secrets` commands with the docker image, like the ones below in the "General Usage" section, you need to make sure you're using the correct prefix depending on which environment you're in. For example, if you wanted to run `detect-secrets scan --exclude-files '<folder_to_ignore>|<file_to_ignore>'`, you would do the following...

#### Windows Powershell and cmd

Replace `detect-secrets` with `docker run -it --rm -v c:/replace/with/your/folder/containing/git/repo:/code ibmcom/detect-secrets:latest`

You can also setup a Powershell script following [doc here](#powershell-docker-command-is-too-long-do-you-have-some-shortcut-for-detect-secrets).

#### Windows git bash

Replace `detect-secrets` with `winpty docker run -it --rm -v /$(pwd):/code ibmcom/detect-secrets:latest`

#### MacOS & Linux

Replace `detect-secrets` with `docker run -it --rm -v $(pwd):/code ibmcom/detect-secrets:latest`

### Powershell docker command is too long, do you have some shortcut for detect-secrets?

Yes, if you are using Powershell, you can download [this file](https://github.com/ibm/detect-secrets/blob/master/user-config/detect-secrets.psm1) and follow the instruction in description to setup a Powershell command wrapper.
