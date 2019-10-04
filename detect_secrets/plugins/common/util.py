try:
    from functools import lru_cache
except ImportError:  # pragma: no cover
    from functools32 import lru_cache

import os
from abc import abstractproperty
from importlib import import_module

from detect_secrets.plugins.base import BasePlugin
from detect_secrets.util import get_root_directory


@lru_cache(maxsize=1)
def get_mapping_from_secret_type_to_class_name():
    """Returns secret_type => plugin classname"""
    return {
        plugin.secret_type: name
        for name, plugin in import_plugins().items()
    }


@lru_cache(maxsize=1)
def import_plugins():
    """
    :rtype: Dict[str, Type[TypeVar('Plugin', bound=BasePlugin)]]
    """
    modules = []
    for root, _, files in os.walk(
        os.path.join(get_root_directory(), 'detect_secrets/plugins'),
    ):
        for filename in files:
            if not filename.startswith('_'):
                modules.append(os.path.splitext(filename)[0])

        # Only want to import top level files
        break

    plugins = {}
    for module_name in modules:
        module = import_module('detect_secrets.plugins.{}'.format(module_name))
        for name in filter(lambda x: not x.startswith('_'), dir(module)):
            plugin = getattr(module, name)
            try:
                if not issubclass(plugin, BasePlugin):
                    continue
            except TypeError:
                # Occurs when plugin is not a class type.
                continue

            # Use this as a heuristic to determine abstract classes
            if isinstance(plugin.secret_type, abstractproperty):
                continue

            plugins[name] = plugin

    return plugins
