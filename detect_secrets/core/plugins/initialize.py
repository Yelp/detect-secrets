from ...settings import get_settings
from ..log import log
from .util import get_mapping_from_secret_type_to_class
from .util import Plugin


def from_secret_type(secret_type: str) -> Plugin:
    """
    :raises: TypeError
    """
    try:
        plugin_type = get_mapping_from_secret_type_to_class()[secret_type]
    except KeyError:
        raise TypeError

    config = get_settings().plugins.get(plugin_type.__name__, {})

    try:
        return plugin_type(**config)
    except TypeError:
        log.error('Unable to initialize plugin!')
        raise


def from_plugin_classname(classname: str) -> Plugin:
    """
    :raises: TypeError
    """
    for plugin_type in get_mapping_from_secret_type_to_class().values():
        if plugin_type.__name__ == classname:
            break
    else:
        log.error(f'Error: No such `{classname}` plugin to initialize.')
        log.error('Chances are you should run `pre-commit autoupdate`.')
        log.error(
            'This error can occur when using a baseline that was made by '
            'a newer detect-secrets version than the one running.',
        )
        raise TypeError

    config = get_settings().plugins.get(classname, {})
    try:
        return plugin_type(**config)
    except TypeError:
        log.error('Unable to initialize plugin!')
        raise
