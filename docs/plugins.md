# Plugins

Plugins are scanners which attempt to find a secret in a given arbitrary line. All plugins must
extend from `detect_secrets.plugins.base.BasePlugin`, though for the most part, extending
`detect_secrets.plugins.base.RegexBasedDetector` should suffice for well-defined secrets.

## Configuring Plugins

A list of configured plugins can be found in the baseline produced:

```
$ detect-secrets scan test_data
{
    "generated_at": "2020-11-13T19:05:03Z",
    "version": "1.0.0",
    "plugins_used": [
        {
            "name": "AWSKeyDetector"
        },
        {
            "name": "Base64HighEntropyString",
            "limit": 4.5
        }
    ],
    "filters_used": [...],
    "results": {...}
}
```

This `name` field refers to the classname of the plugin used. An optional `path` field may be
found if the plugin in question is a locally imported plugin (rather than the plugins that ship
with this tool). Finally, any other values will be used to initialize the class in question (e.g.
`Base64HighEntropyString` will be initialized with the keyword parameter `limit` set to `4.5`).

Plugins are configured through the global `Settings` object. If you are running this as a command
line tool, all plugins will be used by default. However, if you are running this scan as part of
another script, you will need to configure the plugins yourself.

```python
from detect_secrets.core import baseline
from detect_secrets.settings import transient_settings
config = {
    'plugins_used': [
        {
            'name': 'AWSKeyDetector',
        },
    ],
}

with transient_settings(config):
    secrets = baseline.create('.')
```

TODO: Make it easier to "add all plugins" as a non-CLI user.

### Disabling Plugins

If you want to disable plugins, you can use the `--disable-plugin` flag.

If you want to disable all plugins, except for selected ones, you can do something like the
following:

```bash
$ detect-secrets scan --list-all-plugins | \
    grep -v 'BasicAuthDetector' | \
    sed "s#^#--disable-plugin #g | \
    xargs detect-secrets scan test_data
```

### Using Your Own Plugin

Since version 0.14.0, `detect-secrets` allows you to import external files as plugins, so that
you are not restricted to using plugins that have been merged upstream (or maintain your own fork).
This is also especially helpful if you're building your own plugin, and want to test it out before
contributing back to the community.

To do this, you can use the `--plugin` flag in `detect-secrets scan`. For example:

```bash
$ detect-secrets scan --plugin testing/plugins.py test_data
```

This will be reflected in the baseline as such:

```json
{
    ...
    "plugins_used": [
        {
            "name": "AWSKeyDetector"
        },
        {
            "name": "HippoDetector",
            "path": "file:///Users/aaronloo/Documents/github/detect-secrets/testing/plugins.py"
        }
    ]
    ...
}
```

Custom plugins will still need to extend `detect_secrets.plugins.base.BasePlugin`, and adhere to
the interface for any other plugin (see [Writing Your Own Plugin](#Writing-Your-Own-Plugin)). If
there is something wrong with your plugin initialization, it will raise a `TypeError`.

> :warning: **WARNING** :warning:
>
> By its very nature, the use of custom plugins essentially executes arbitrary code (by importing
  an arbitrary file). Therefore, caution should be exercised when doing so. For a deeper dive into
  the security assumptions made through this feature, check out
  `detect_secrets.util.importlib.import_file_as_module`.

## Writing Your Own Plugin

If you're looking to implement a regex-based secret scan, check out
`detect_secrets.plugins.basic_auth.BasicAuthDetector` for a clean example of adding a
`RegexBasedDetector` to your suite of plugins.

If you want something a little more advanced, with **in-built secret verification**, check out
`detect_secrets.plugins.stripe.StripeDetector`.

The general workflow for adding a new plugin is as such:

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

### Verified Secrets

**Secret Verifiability** was a concept introduced since version 0.12.4, and provides the ability
to decrease false positives by making an API call to a server to check whether a `PotentialSecret`
is indeed real. This can be extremely useful for specific secrets (e.g. `RegexBasedDetector`
subclasses) since we are able to determine which server to contact.

You are able to configure your verification settings via the `--no-verify` or `--only-verified`
flags in `detect-secrets scan`. By default, `detect-secrets` will attempt to verify all secrets,
and display both unverified and verified true secrets.

This is implemented as the [built-in filter](filters.md)
`detect_secrets.filters.common.is_ignored_due_to_verification_policies`, which invokes each
plugin's `verify` function. Furthermore, it leverages the dependency injection system, so `verify`
functions **MUST** declare a dependency on some combination of the following variables:

| Variable Name | Type                                           | Description                       |
|---------------|------------------------------------------------|-----------------------------------|
| `secret`      | string                                         | The raw secret value.             |
| `context`     | `detect_secrets.util.code_snippet.CodeSnippet` | Lines of code surrounding secret. |


The context is especially useful since research has shown
([source](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf):
Section V-D) that there's an 80% chance of finding a multi-factor secret (e.g. username + password)
within five lines of context, before and after a secret.

For more information on how to verify secrets, check out: https://github.com/streaak/keyhacks.

### Tips

- There should be a total of three modified files in a minimal new plugin: the
  plugin file, it's corresponding test, and an updated CHANGELOG.
