# Cheat Sheet

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Scan](#scan)
  - [Generate baseline](#generate-baseline)
  - [Re-scan and update baseline](#re-scan-and-update-baseline)
  - [Scan without verifying tokens](#scan-without-verifying-tokens)
  - [Choose plugins to use](#choose-plugins-to-use)
  - [Choose files to scan](#choose-files-to-scan)
  - [Ad-hoc scan on a single string](#ad-hoc-scan-on-a-single-string)
  - [Exclude something from the scan](#exclude-something-from-the-scan)
  - [Customize the entropy limit](#customize-the-entropy-limit)
- [Audit](#audit)
  - [Audit the baseline file](#audit-the-baseline-file)
  - [Display audit results](#display-audit-results)
- [pre-commit hook](#pre-commit-hook)
  - [Python pre-commit framework](#python-pre-commit-framework)
    - [Update baseline](#update-baseline)
    - [Update baseline with all plugins](#update-baseline-with-all-plugins)
    - [Update baseline while skipping some plugins](#update-baseline-while-skipping-some-plugins)
    - [Fail pre-commit if there are non-audited entries](#fail-pre-commit-if-there-are-non-audited-entries)
  - [Husky](#husky)
  - [CLI](#cli)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Scan

### Generate baseline

```sh
# Output to stdout
detect-secrets scan

# Write to a baseline file
detect-secrets scan --update .secrets.baseline
```

### Re-scan and update baseline

```sh
# By default, detect-secrets uses plugins specified in the baseline file
detect-secrets scan --update .secrets.baseline

# Additional CLI options can be used to overwrite the plugins specified in baseline
detect-secrets scan --update .secrets.baseline --use-all-plugins
```

### Scan without verifying tokens

```sh
detect-secrets scan --no-verify
```

### Choose plugins to use

```sh
# Use all plugins
detect-secrets scan --use-all-plugins

# Skip some plugins
detect-secrets scan --use-all-plugins --no-keyword-scan --no-db2-scan
```

### Choose files to scan

```sh
# Scan files tracked by git
# By default, files in .gitignore are ignored
detect-secrets scan

# Scan on specific files
detect-secrets scan file1 file2

# Scan all files except for .gitignore
detect-secrets scan --all-files
```

### Ad-hoc scan on a single string

```sh
# This also displays all supported plugins
detect-secrets scan --string "api_key='something'"

# Skip a specific plugin
detect-secrets scan --string "api_key='something'" --no-keyword-scan
```

### Exclude something from the scan

```sh
# Exclude Python regex-matched files and directories, applies to all plugins
detect-secrets scan --exclude-files 'package-lock.json|another_file_name|dir_name'

# Exclude Python regex-matched lines, applies to all plugins
detect-secrets scan package-lock.json --exclude-lines 'integrity'

# Exclude a list of keywords defined in a file, applies to all plugins
echo REPLACE_ME > word_list_file
detect-secrets scan --string "api_key='REPLACE_ME'" --word-list word_list_file

# Exclude Python regex-matched keywords, applies to the keyword plugin only
detect-secrets scan --string "api_key='something'" --keyword-exclude "api_key"
```

### Customize the entropy limit

```sh
detect-secrets scan --base64-limit <new_limit_in_number>
detect-secrets scan --hex-limit <new_limit_in_number>
```

## Audit

### Audit the baseline file

```sh
detect-secrets audit .secrets.baseline
```

### Display audit results

```sh
detect-secrets audit --display-results .secrets.baseline
```

## pre-commit hook

Supports most options from `detect-secrets scan`

### Python pre-commit framework

#### Update baseline

```yaml
# .pre-commit-config.yaml, placed in the root directory of the git repository
- repo: https://github.com/ibm/detect-secrets
  rev: master
  hooks:
      - id: detect-secrets
        args: [--baseline, .secrets.baseline]
```

#### Update baseline with all plugins

```yaml
# .pre-commit-config.yaml, placed in the root directory of the git repository
- repo: https://github.com/ibm/detect-secrets
  rev: master
  hooks:
      - id: detect-secrets
        args: [--baseline, .secrets.baseline, --use-all-plugins]
```

#### Update baseline while skipping some plugins

```yaml
# .pre-commit-config.yaml, placed in the root directory of the git repository
- repo: https://github.com/ibm/detect-secrets
  rev: master
  hooks:
      - id: detect-secrets
        args:
            [
                --baseline,
                .secrets.baseline,
                --use-all-plugins,
                --no-keyword-scan,
            ]
```

#### Fail pre-commit if there are non-audited entries

Fail pre-commit if there are non-auditied entries in baseline file, even if the entries are in files not part of current commit.

```yaml
# .pre-commit-config.yaml, placed in the root directory of the git repository
- repo: https://github.com/ibm/detect-secrets
  rev: master
  hooks:
      - id: detect-secrets
        args:
            [
                --baseline,
                .secrets.baseline,
                --use-all-plugins,
                --fail-on-unaudited,
            ]
```

### Husky

v6+ (file: `.husky/pre-commit`):

```bash
#!/bin/sh
. "$(dirname "$0")/_/husky.sh"

detect-secrets-hook --baseline .secrets.baseline $(git diff --cached --name-only)
```

Before v6 (file: `package.json`):

```json
"husky": {
    "hooks": {
        "pre-commit": "detect-secrets-hook --baseline .secrets.baseline $(git diff --cached --name-only)"
    }
}
```

### CLI

```sh
detect-secrets-hook --baseline .secrets.baseline --use-all-plugins
```
