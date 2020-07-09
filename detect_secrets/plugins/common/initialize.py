"""Intelligent initialization of plugins."""
from detect_secrets.core.log import log
from detect_secrets.core.usage import PluginOptions
from detect_secrets.plugins.common.util import get_mapping_from_secret_type_to_class_name
from detect_secrets.plugins.common.util import import_plugins


def from_parser_builder(
    plugins_dict,
    custom_plugin_paths,
    exclude_lines_regex=None,
    automaton=None,
    should_verify_secrets=False,
):
    """
    :param plugins_dict: plugins dictionary received from ParserBuilder.
        See example in tests.core.usage_test.

    :type custom_plugin_paths: Tuple[str]
    :param custom_plugin_paths: possibly empty tuple of paths that have custom plugins.

    :type exclude_lines_regex: str|None
    :param exclude_lines_regex: optional regex for ignored lines.

    :type automaton: ahocorasick.Automaton|None
    :param automaton: optional automaton for ignoring certain words.

    :type should_verify_secrets: bool

    :returns: tuple of initialized plugins
    """
    output = []

    for plugin_classname in plugins_dict:
        output.append(
            from_plugin_classname(
                plugin_classname,
                custom_plugin_paths=custom_plugin_paths,
                exclude_lines_regex=exclude_lines_regex,
                automaton=automaton,
                should_verify_secrets=should_verify_secrets,
                **plugins_dict[plugin_classname]
            ),
        )

    return tuple(output)


def _get_prioritized_parameters(plugins_dict, is_using_default_value_map, prefer_default=True):
    """
    :type plugins_dict: dict(plugin_name => plugin_params)
    :param plugin_dict: mapping of plugin name to all plugin params

    :type is_using_default_value_map: dict(str => bool)
    :param is_using_default_value_map: mapping of parameter name to whether its value is derived
        from a default value.

    :param prefer_default: if True, will yield if plugin parameters are from default values.
        Otherwise, will yield if plugin parameters are *not* from default values.
    """
    for plugin_name, plugin_params in plugins_dict.items():
        for param_name, param_value in plugin_params.items():
            is_using_default = is_using_default_value_map.get(param_name, False)
            if is_using_default == prefer_default:
                yield plugin_name, param_name, param_value


def merge_plugins_from_baseline(baseline_plugins, args, automaton):
    """
    :type baseline_plugins: tuple of BasePlugin
    :param baseline_plugins: BasePlugin instances from baseline file

    :type args: dict
    :param args: dictionary of arguments parsed from usage

    :type automaton: ahocorasick.Automaton|None
    :param automaton: optional automaton for ignoring certain words.

    param priority is input param > baseline param > default

    :returns: tuple of initialized plugins
    """
    def _remove_key(d, key):
        r = dict(d)
        r.pop(key)
        return r

    baseline_plugins_dict = {
        vars(plugin)['name']: _remove_key(vars(plugin), 'name')
        for plugin in baseline_plugins
    }

    # Use input plugin as starting point
    if args.use_all_plugins:
        # Input param and default param are used
        plugins_dict = dict(args.plugins)

        # Baseline param priority > default
        for plugin_name, param_name, param_value in _get_prioritized_parameters(
            baseline_plugins_dict,
            args.is_using_default_value,
            prefer_default=True,
        ):
            try:
                plugins_dict[plugin_name][param_name] = param_value
            except KeyError:  # pragma: no cover
                log.warning(
                    'Baseline contains plugin {} which is not in all plugins! Ignoring...',
                    plugin_name,
                )

        return from_parser_builder(
            plugins_dict,
            custom_plugin_paths=args.custom_plugin_paths,
            exclude_lines_regex=args.exclude_lines,
            automaton=automaton,
            should_verify_secrets=not args.no_verify,
        )

    # Use baseline plugin as starting point
    disabled_plugins = PluginOptions.get_disabled_plugins(args)
    plugins_dict = {
        plugin_name: plugin_params
        for plugin_name, plugin_params in baseline_plugins_dict.items()
        if plugin_name not in disabled_plugins
    }

    # Input param priority > baseline
    input_plugins_dict = dict(args.plugins)
    for plugin_name, param_name, param_value in _get_prioritized_parameters(
        input_plugins_dict,
        args.is_using_default_value,
        prefer_default=False,
    ):
        try:
            plugins_dict[plugin_name][param_name] = param_value
        except KeyError:
            log.warning(
                '{} specified, but {} not configured! Ignoring...',
                ''.join(['--', param_name.replace('_', '-')]),
                plugin_name,
            )

    return from_parser_builder(
        plugins_dict,
        custom_plugin_paths=args.custom_plugin_paths,
        exclude_lines_regex=args.exclude_lines,
        automaton=automaton,
        should_verify_secrets=not args.no_verify,
    )


def from_plugin_classname(
    plugin_classname,
    custom_plugin_paths,
    exclude_lines_regex=None,
    automaton=None,
    should_verify_secrets=False,
    **kwargs
):
    """Initializes a plugin class, given a classname and kwargs.

    :type plugin_classname: str
    :param plugin_classname: subclass of BasePlugin.

    :type custom_plugin_paths: Tuple[str]
    :param custom_plugin_paths: possibly empty tuple of paths that have custom plugins.

    :type exclude_lines_regex: str|None
    :param exclude_lines_regex: optional regex for ignored lines.

    :type automaton: ahocorasick.Automaton|None
    :param automaton: optional automaton for ignoring English-words.

    :type should_verify_secrets: bool
    """
    try:
        klass = import_plugins(custom_plugin_paths)[plugin_classname]
    except KeyError:
        log.error('Error: No such `{}` plugin to initialize.'.format(plugin_classname))
        log.error('Chances are you should run `pre-commit autoupdate`.')
        log.error(
            'This error can occur when using a baseline that was made by '
            'a newer detect-secrets version than the one running.',
        )
        log.error(
            'It can also occur if the baseline has custom plugin paths, '
            'but the `--custom-plugins` option was not passed.',
        )
        raise TypeError

    try:
        instance = klass(
            exclude_lines_regex=exclude_lines_regex,
            automaton=automaton,
            should_verify=should_verify_secrets,
            **kwargs
        )
    except TypeError:
        log.error('Unable to initialize plugin!')
        raise

    return instance


def from_secret_type(secret_type, plugins_used, custom_plugin_paths):
    """
    Note: Only called from audit.py

    :type secret_type: str
    :param secret_type: unique identifier for plugin type

    :type plugins_used: list
    :param plugins_used: output of "plugins_used" in baseline. e.g.
        >>> [
        ...     {
        ...         'name': 'Base64HighEntropyString',
        ...         'base64_limit': 4.5,
        ...     },
        ... ]

    :type custom_plugin_paths: Tuple[str]
    :param custom_plugin_paths: possibly empty tuple of paths that have custom plugins.
    """
    mapping = get_mapping_from_secret_type_to_class_name(custom_plugin_paths)
    try:
        classname = mapping[secret_type]
    except KeyError:
        return None

    for plugin in plugins_used:
        if plugin['name'] == classname:
            plugin_init_vars = plugin.copy()
            plugin_init_vars.pop('name')

            return from_plugin_classname(
                classname,
                custom_plugin_paths=custom_plugin_paths,

                # `audit` does not need to
                # perform exclusion, filtering or verification
                exclude_lines_regex=None,
                automaton=None,
                should_verify_secrets=False,

                **plugin_init_vars
            )
