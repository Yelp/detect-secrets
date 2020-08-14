import importlib.util
import inspect
import os
from abc import abstractproperty
from functools import lru_cache

from detect_secrets.plugins.base import BasePlugin
from detect_secrets.util import get_root_directory


@lru_cache(maxsize=1)
def get_mapping_from_secret_type_to_class_name(custom_plugin_paths):
    """Returns dictionary of secret_type => plugin classname"""
    return {
        plugin.secret_type: name
        for name, plugin in import_plugins(custom_plugin_paths).items()
    }


def _dynamically_import_module(path_to_import, module_name):
    """
    :type path_to_import: str
    :type module_name: str

    :rtype: module
    """
    spec = importlib.util.spec_from_file_location(
        module_name,
        path_to_import,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _is_valid_concrete_plugin_class(attr):
    """
    :type attr: Any

    :rtype: bool
    """
    return (
        inspect.isclass(attr)
        and
        issubclass(attr, BasePlugin)
        and
        # Heuristic to determine abstract classes
        not isinstance(attr.secret_type, abstractproperty)
    )


@lru_cache(maxsize=1)
def import_plugins(custom_plugin_paths):
    """
    :type custom_plugin_paths: tuple(str,)
    :param custom_plugin_paths: possibly empty tuple of paths that have custom plugins.

    :rtype: Dict[str, Type[TypeVar('Plugin', bound=BasePlugin)]]
    """
    path_and_module_name_pairs = []

    # Handle files
    for path_to_import in custom_plugin_paths:
        if os.path.isfile(path_to_import):
            # [:-3] for removing '.py'
            module_name = path_to_import[:-3].replace('/', '.')
            path_and_module_name_pairs.append(
                (
                    path_to_import,
                    module_name,
                ),
            )

    # Handle directories
    regular_plugins_dir = os.path.join(
        get_root_directory(),
        'detect_secrets/plugins',
    )
    plugin_dirs = (
        [regular_plugins_dir]
        +
        list(
            filter(
                lambda path: (
                    os.path.isdir(path)
                ),
                custom_plugin_paths,
            ),
        )
    )
    for plugin_dir in plugin_dirs:
        for filename in os.listdir(
            plugin_dir,
        ):
            if (
                filename.startswith('_')
                or not filename.endswith('.py')
            ):
                continue

            path_to_import = os.path.join(
                plugin_dir,
                filename,
            )

            # [:-3] for removing '.py'
            if plugin_dir == regular_plugins_dir:
                module_name = 'detect_secrets.plugins.{}'.format(filename[:-3])
            else:
                module_name = path_to_import[:-3].replace('/', '.')
            path_and_module_name_pairs.append(
                (
                    path_to_import,
                    module_name,
                ),
            )

    # Do the importing
    plugins = {}
    for path_to_import, module_name in path_and_module_name_pairs:
        module = _dynamically_import_module(
            path_to_import,
            module_name,
        )
        for attr_name in filter(
            lambda attr_name: not attr_name.startswith('_'),
            dir(module),
        ):
            attr = getattr(module, attr_name)
            if _is_valid_concrete_plugin_class(attr):
                plugins[attr_name] = attr

    return plugins
