"""Intelligent initialization of plugins."""
try:
    from functools import lru_cache
except ImportError:
    from functools32 import lru_cache

from ..aws import AWSKeyDetector                            # noqa: F401
from ..base import BasePlugin
from ..basic_auth import BasicAuthDetector                  # noqa: F401
from ..high_entropy_strings import Base64HighEntropyString  # noqa: F401
from ..high_entropy_strings import HexHighEntropyString     # noqa: F401
from ..keyword import KeywordDetector                       # noqa: F401
from ..private_key import PrivateKeyDetector                # noqa: F401
from ..slack import SlackDetector                           # noqa: F401
from detect_secrets.core.log import log


def from_parser_builder(plugins_dict):
    """
    :param plugins_dict: plugins dictionary received from ParserBuilder.
        See example in tests.core.usage_test.
    :returns: tuple of initialized plugins
    """
    output = []
    for plugin_name in plugins_dict:
        output.append(from_plugin_classname(
            plugin_name,
            **plugins_dict[plugin_name]
        ))

    return tuple(output)


def merge_plugin_from_baseline(baseline_plugins, args):
    """
    :type baseline_plugins: tuple of BasePlugin
    :param baseline_plugins: BasePlugin instances from baseline file

    :type args: dict
    :param args: diction of arguments parsed from usage

    param priority: input param > baseline param > default

    :Returns tuple of initialized plugins
    """
    def _remove_key(d, key):
        r = dict(d)
        r.pop(key)
        return r
    baseline_plugins_dict = {
        vars(plugin)["name"]: _remove_key(vars(plugin), "name")
        for plugin in baseline_plugins
    }

    # Use input plugin as starting point
    if args.use_all_plugins:
        # input param and default param are used
        plugins_dict = dict(args.plugins)

        # baseline param priority > default
        for plugin_name, plugin_params in list(baseline_plugins_dict.items()):
            for param_name, param_value in list(plugin_params.items()):
                from_default = args.param_from_default.get(param_name, False)
                if from_default:
                    try:
                        plugins_dict[plugin_name][param_name] = param_value
                    except KeyError:
                        log.warning(
                            'Baseline contain plugin %s which is not in all plugins! Ignoring...'
                            % (plugin_name),
                        )

        return from_parser_builder(plugins_dict)

    # Use baseline plugin as starting point
    plugins_dict = baseline_plugins_dict
    if args.disabled_plugins:
        for plugin_name in args.disabled_plugins:
            if plugin_name in plugins_dict:
                plugins_dict.pop(plugin_name)

    # input param priority > baseline
    input_plugins_dict = dict(args.plugins)
    for plugin_name, plugin_params in list(input_plugins_dict.items()):
        for param_name, param_value in list(plugin_params.items()):
            from_default = args.param_from_default.get(param_name, False)
            if from_default is False:
                try:
                    plugins_dict[plugin_name][param_name] = param_value
                except KeyError:
                    log.warning(
                        '%s specified, but %s not configured! Ignoring...'
                        % ("".join(["--", param_name.replace("_", "-")]), plugin_name),
                    )

    return from_parser_builder(plugins_dict)


def from_plugin_classname(plugin_classname, **kwargs):
    """Initializes a plugin class, given a classname and kwargs.

    :type plugin_classname: str
    :param plugin_classname: subclass of BasePlugin
    """
    klass = globals()[plugin_classname]

    # Make sure the instance is a BasePlugin type, before creating it.
    if not issubclass(klass, BasePlugin):
        raise TypeError

    try:
        instance = klass(**kwargs)
    except TypeError:
        log.warning(
            'Unable to initialize plugin!',
        )
        raise

    return instance


def from_secret_type(secret_type, settings):
    """
    :type secret_type: str
    :param secret_type: unique identifier for plugin type

    :type settings: list
    :param settings: output of "plugins_used" in baseline. e.g.
        >>> [
        ...     {
        ...         'name': 'Base64HighEntropyString',
        ...         'base64_limit': 4.5,
        ...     },
        ... ]
    """
    mapping = _get_mapping_from_secret_type_to_class_name()
    try:
        classname = mapping[secret_type]
    except KeyError:
        return None

    for plugin in settings:
        if plugin['name'] == classname:
            plugin_init_vars = plugin.copy()
            plugin_init_vars.pop('name')

            return from_plugin_classname(
                classname,
                **plugin_init_vars
            )


@lru_cache(maxsize=1)
def _get_mapping_from_secret_type_to_class_name():
    """Returns secret_type => plugin classname"""
    mapping = {}
    for key, value in globals().items():
        try:
            if issubclass(value, BasePlugin) and value != BasePlugin:
                mapping[value.secret_type] = key
        except TypeError:
            pass

    return mapping
