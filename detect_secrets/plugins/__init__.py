from collections import namedtuple

from .base import BasePlugin
from .high_entropy_strings import Base64HighEntropyString   # noqa: F401
from .high_entropy_strings import HexHighEntropyString      # noqa: F401
from detect_secrets.core.log import CustomLog


_SensitivityValues = namedtuple(
    'SensitivityValues',
    [
        'base64_limit',
        'hex_limit',
    ]
)


class SensitivityValues(_SensitivityValues):

    def __new__(cls, base64_limit=None, hex_limit=None, **kwargs):
        if base64_limit is None and 'Base64HighEntropyString' in kwargs:
            base64_limit = kwargs['Base64HighEntropyString']

        if hex_limit is None and 'HexHighEntropyString' in kwargs:
            hex_limit = kwargs['HexHighEntropyString']

        return super(SensitivityValues, cls).__new__(
            cls,
            base64_limit=base64_limit,
            hex_limit=hex_limit,
        )


_CustomLogObj = CustomLog()


def _convert_sensitivity_values_to_class_tuple(sensitivity_values):
    """
    :param sensitivity_values: SensitivityValues
    :return: tuple in the format (<plugin_class_name>, <value_to_initialize_it>)
             This way, we can initialize the class with <plugin_class_name>(<value>)
    """
    mapping = {
        'base64_limit': 'Base64HighEntropyString',
        'hex_limit': 'HexHighEntropyString',
    }

    output = []
    for key in sensitivity_values._fields:
        if key in mapping and getattr(sensitivity_values, key) is not None:
            output.append((mapping[key], getattr(sensitivity_values, key),))

    return tuple(output)


def initialize(plugin_config):
    """Converts a list of plugin names (and corresponding initializing parameters)
    to instances of plugins, for scanning purposes.

    :type plugin_config: SensitivityValues

    :return: list of BasePlugins
    """
    output = []
    if not isinstance(plugin_config, SensitivityValues):
        return output

    plugin_config_tuple = _convert_sensitivity_values_to_class_tuple(plugin_config)

    for plugin, value in plugin_config_tuple:
        klass = globals()[plugin]

        # Make sure the instance is a BasePlugin type, before creating it.
        if not issubclass(klass, BasePlugin):
            continue

        try:
            instance = klass(value)
        except TypeError:
            _CustomLogObj.getLogger().warning(
                'Unable to initialize plugin!'
            )
            continue

        output.append(instance)

    return output
