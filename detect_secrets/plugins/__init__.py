from collections import namedtuple

from .base import BasePlugin
from .high_entropy_strings import Base64HighEntropyString   # noqa: F401
from .high_entropy_strings import HexHighEntropyString      # noqa: F401
from .private_key import PrivateKeyDetector                 # noqa: F401
from detect_secrets.core.log import CustomLog


_CustomLogObj = CustomLog()


class SensitivityValues(namedtuple(
    'SensitivityValues',
    [
        'base64_limit',
        'hex_limit',
        'private_key_detector',
    ]
)):
    """Server configuration to determine which plugins to run per repo."""

    def __new__(
            cls,
            base64_limit=None,
            hex_limit=None,
            private_key_detector=False,
            **kwargs
    ):
        """
        We perform this additional mapping logic, for more readable config files.
        This way, you can specify the plugin's class in the config file, and
        `initialize` will be able to create a SensitivityValues namedtuple from it.

        Example:
        >>> tracked:
                repo: git@github.com:yelp/detect-secrets.git
                plugins:
                    Base64HighEntropyString: 4
                    PrivateKeyDetector: true

        :type base64_limit: float; between 0.0 and 8.0.
        :param base64_limit: min entropy needed to trigger alert.

        :type hex_limit: float; between 0.0 and 8.0
        :param hex_limit: same as base64_limit.

        :type private_key_detector: bool
        :param private_key_detector: True to enable private key scanning.
        """
        if base64_limit is None and 'Base64HighEntropyString' in kwargs:
            base64_limit = kwargs['Base64HighEntropyString']

        if hex_limit is None and 'HexHighEntropyString' in kwargs:
            hex_limit = kwargs['HexHighEntropyString']

        if 'PrivateKeyDetector' in kwargs:
            private_key_detector = kwargs['PrivateKeyDetector']
        private_key_detector = bool(private_key_detector)

        return super(SensitivityValues, cls).__new__(
            cls,
            base64_limit=base64_limit,
            hex_limit=hex_limit,
            private_key_detector=private_key_detector,
        )


def initialize(plugin_config):
    """
    Converts a list of plugin names (and corresponding initializing parameters)
    to instances of plugins, for scanning purposes.

    :type plugin_config: SensitivityValues

    :return: list of BasePlugins
    """
    output = []
    if not isinstance(plugin_config, SensitivityValues):
        return output

    plugin_config_tuple = _convert_sensitivity_values_to_class_tuple(plugin_config)

    for plugin, value in plugin_config_tuple:
        if not value:
            continue

        try:
            output.append(_initialize_plugin(plugin, value))
        except TypeError:
            pass

    return output


def initialize_plugins(plugins):
    """
    NOTE: This currently assumes there is at most one initialization parameter.
    If this invariant changes, this will need to be modified.

    NOTE: This is very similar to initialize right now (and probably,
    where we want to head towards in the future?) However, the previous is
    necessary until we fix server related code.

    :param plugins: plugins dictionary received from ParserBuilder
                    See example in tests.core.usage_test.
    :return: tuple of initialized plugins
    """
    output = []
    for plugin_name in plugins:
        init_values = plugins[plugin_name]

        args = []
        if init_values:
            key = list(init_values.keys())[0]
            args.append(init_values[key][0])

        output.append(_initialize_plugin(plugin_name, *args))

    return tuple(output)


def _initialize_plugin(plugin_classname, *args):
    klass = globals()[plugin_classname]

    # Make sure the instance is a BasePlugin type, before creating it.
    if not issubclass(klass, BasePlugin):
        raise TypeError

    try:
        instance = klass(*args)
    except TypeError:
        _CustomLogObj.getLogger().warning(
            'Unable to initialize plugin!'
        )
        raise

    return instance


def _convert_sensitivity_values_to_class_tuple(sensitivity_values):
    """
    :param sensitivity_values: SensitivityValues
    :return: tuple in the format (<plugin_class_name>, <value_to_initialize_it>)
             This way, we can initialize the class with <plugin_class_name>(<value>)

    Example:
        >>> [ ('HexHighEntropyString', 3), ('PrivateKeyDetector', true), ]
    """
    mapping = {
        'base64_limit': 'Base64HighEntropyString',
        'hex_limit': 'HexHighEntropyString',
        'private_key_detector': 'PrivateKeyDetector',
    }

    output = []
    for key in sensitivity_values._fields:
        if key in mapping and getattr(sensitivity_values, key) is not None:
            output.append((mapping[key], getattr(sensitivity_values, key),))

    return tuple(output)
