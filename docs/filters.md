# Filters

Filters are functions that return a boolean value to indicate whether a specific condition
should be skipped.

**Example #1:**

This is an example of a filter:

```python
# source: detect_secrets.filters.common
def is_invalid_file(filename: str) -> bool:
    return not os.path.isfile(filename)
```

This will ignore all invalid files, and ensure that we don't perform unnecessary scans on
files that don't exist.

**Example #2:**

```python
# source: detect_secrets.filters.heuristic
def is_potential_uuid(secret: str) -> bool:
    return bool(_get_uuid_regex().search(secret))

@lru_cache(maxsize=1)
def _get_uuid_regex() -> Pattern:
    return re.compile(
        r'[a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12}',
        re.IGNORECASE,
    )
```

This above example is another example of a filter. Unlike the former example, this serves
to make sure that UUIDs aren't classified as secrets by returning `True` (hence, skipping)
if the raw secret value looks like a UUID.

## Built-in Filters

This is a current list of filters that ship with `detect-secrets`. All filters are found under
the `detect_secrets.filters` namespace.

| Name                                             | Description                                                                         |
|--------------------------------------------------|-------------------------------------------------------------------------------------|
| `allowlist.is_line_allowlisted`                  | Powers the [inline allowlisting](../README.md#Inline-Allowlisting) functionality.   |
| `common.is_invalid_file`                         | Ignores files that are not files (e.g. links).                                      |
| `common.is_baseline_file`                        | Ignores the baseline file itself.                                                   |
| `common.is_ignored_due_to_verification_policies` | Powers secret verification functionality.                                           |
| `gibberish.should_exclude_secret`                | Excludes secrets that are not gibberish looking strings.                            |
| `heuristic.is_indirect_reference`                | Primarily for `KeywordDetector`, filters secrets like `secret = get_secret_key()`.  |
| `heuristic.is_likely_id_string`                  | Ignores secret values prefixed with `id`.                                           |
| `heuristic.is_lock_file`                         | Ignores common lock files.                                                          |
| `heuristic.is_non_text_file`                     | Ignores non-text files (e.g. archives, images).                                     |
| `heuristic.is_not_alphanumeric_string`           | Ignores secrets that do not have a single alphanumeric character in it.             |
| `heuristic.is_potential_uuid`                    | Ignores uuid looking secret values.                                                 |
| `heuristic.is_prefixed_with_dollar_sign`         | Primarily for `KeywordDetector`, filters secrets like `secret = $variableName;`.    |
| `heuristic.is_sequential_string`                 | Ignores secrets like `abcdefg`.                                                     |
| `heuristic.is_swagger_file`                      | Ignores swagger files and paths, like swagger-ui.html or /swagger/.                 |
| `heuristic.is_templated_secret`                  | Ignores secrets like `secret = <key>`, `secret = {{key}}` and `secret = ${key}`.    |
| `regex.should_exclude_line`                      | Powers the [`--exclude-lines` functionality](../README.md#--exclude-lines).         |
| `regex.should_exclude_file`                      | Powers the [`--exclude-files` functionality](../README.md#--exclude-files).         |
| `regex.should_exclude_secret`                    | Powers the [`--exclude-secrets` functionality](../README.md#--exclude-secrets).     |
| `wordlist.should_exclude_secret`                 | Powers the [`--word-list` functionality](../README.md#--word-list).                 |

## Configuring Filters

As of version 1.0, all built-in filters are included in every scan. A list of these can be
found in the baseline produced:

```bash
$ detect-secrets scan test_data
{
    "generated_at": "2020-11-13T19:05:03Z",
    "version": "1.0.0",
    "plugins_used": [...],
    "filters_used": [
        {
            "path": "detect_secrets.filters.heuristic.is_potential_uuid"
        },
        {
            "path": "detect_secrets.filters.common.is_ignored_due_to_verification_policies",
            "min_level": 2,
        }
        ...
    ],
    "results": {...}
}
```

This `path` value specifies the import path for the filter function to be used. If there are
any additional values that are needed for filter configuration (e.g. `min_level` in
`is_ignored_due_to_verification_policies`), they will also be listed within the same dictionary.

There are also a set of **default filters** that are added to every scan.
These can be found in
[`detect_secrets.settings.Settings.DEFAULT_FILTERS`](../detect_secrets/settings.py)
and power global exclusion policies (e.g. inline allowlisting via `pragma: allowlist secret`).
For the sake of brevity, these default filters are not included in the baseline output.

### Disabling Filters

You can disable any filters with the `--disable-filter` flag. For example:

```bash
$ detect-secrets scan test_data --disable-filter detect_secrets.filters.heuristic.is_prefixed_with_dollar_sign
```

If you're running `detect-secrets` as a package, you can specify the filters you want by
customizing your own settings object. e.g.

```python
from detect_secrets.core import baseline
from detect_secrets.settings import transient_settings
config = {
    'filters_used': [
        {
            'path': 'detect_secrets.filters.heuristic.is_potential_uuid',
        },
    ],
}

with transient_settings(config):
    secrets = baseline.create('.')
```

### Using Your Own Filters

You can provide your own filters with the `--filter` flag. For example, if you wanted to [provide
a custom file](#Writing-Your-Own-Filter), you can provide it in the format:
`/path/to/file::function_name`. For example:

```bash
$ cat custom_filter.py
def is_invalid_secret(secret: str) -> bool:
    return secret == 'invalid'

$ detect-secrets scan --filter custom_filter.py::is_invalid_secret
```

You can also provide an import path to the filter function you desire:

```
$ detect-secrets scan --filter detect_secrets.filters.heuristic.is_md5_string
```

## Writing Your Own Filter

If you want to systematically exclude results from the scan, filters are the way to go. The most
common filters are configured via `--exclude-lines` and `--exclude-files`, however, if you need
a more custom solution for your environment, you may want to experiment with custom filters!

### A Word About Filter Internals

Before you can write your own filter, it's important to understand how they fit into the larger
secret scanning engine.

Filters are dynamically executed as part of the scan process, and are sequentially run based on
the information that is currently known at that specific stage of the process. For example, when you scan a file, this is the process it takes:

1. Check to see whether the filename should be scanned (filter)

2. Obtain lines by processing file.

3. For each line,

    a. Check to see whether the line should be scanned (filter)

    b. For each plugin, attempt to find a secret on that line, and determine whether it is
       indeed a secret (filter)

4. Aggregate secrets.

In this example, you can see that step #1's filters will operate on filenames alone (e.g.
**Example #1** above), yet step #3b will have the filename, line, secret found, as well as the
plugin which found it.

Therefore, filters need to declare the variables that they will need to make a decision. Then,
the dependency injection system will auto-magically call the registered filters based on the
information available to it at the time.

For more details, check out `detect_secrets/core/scan.py`.

### Pre-defined Variables

Filters **MUST** only depend on some combination of the following variables:

| Variable Name | Type                                           | Description                       |
|---------------|------------------------------------------------|-----------------------------------|
| `filename`    | string                                         | The file path being scanned.      |
| `line`        | string                                         | The line being scanned.           |
| `plugin`      | `detect_secrets.core.plugins.util.Plugin`      | The plugin that found the secret. |
| `secret`      | string                                         | The raw secret value.             |
| `context`     | `detect_secrets.util.code_snippet.CodeSnippet` | Lines of code surrounding secret. |

### Best Practices

#### 1. Cache When Possible

Expect that your filter function will be called multiple times during a scan process. Imagine: if
your filter operates on lines, it would need to be called for every line, in every file that you
scan! If your filter has a long initialization process, it will considerably slow down the overall
scan process.

**Example #2** demonstrates a better way to accomplish this. By caching the compiled regex as such,
the regex will only need to be created once for the entire scan, avoiding unnecessary detriments
in scan speed.

#### 2. Cache Loaded Settings

The `detect_secrets.filters.wordlist.should_exclude_secret` is a fantastic example of this.
This wordlist filter leverages the Aho-Corasick algorithm to process a list of words and to
determine whether a secret value is in the list of known false positives. However, the
initialization process of the automaton engine is a slow one -- and definitely not something we
want to be initializing for **every** secret found!

To get around this problem, we `initialize` the automaton once on load, then cache it so that all
future executions will merely use the cached version.

Furthermore, the pattern of reading the filter settings from the global `Settings` object is also
encouraged: read it once, setup your filter, and have smooth executions for the rest of the scan.
