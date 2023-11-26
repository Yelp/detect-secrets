from __future__ import annotations

import inspect
from functools import lru_cache
from types import ModuleType
from typing import Any
from typing import cast
from typing import Dict
from typing import Generator

from ... import plugins
from ...plugins.base import BasePlugin
from ...settings import get_settings
from ...util.importlib import import_file_as_module
from ...util.importlib import import_types_from_module
from ...util.importlib import import_types_from_package


@lru_cache(maxsize=1)
def get_mapping_from_secret_type_to_class() -> Dict[str, type[BasePlugin]]:
    output = {}
    for plugin_class in import_types_from_package(
        plugins,
        filter=lambda x: not _is_valid_plugin(x),
    ):
        output[plugin_class.secret_type] = plugin_class

    # Load custom plugins.
    # NOTE: It's entirely possible that once the baseline is created, it is modified by
    # someone to cause this to break (e.g. arbitrary imports from unexpected places).
    # However, this falls under the same security assumptions as listed in
    # `import_file_as_module`.
    for config in get_settings().plugins.values():
        if 'path' not in config:
            continue

        # Only supporting file schema right now.
        filename = config['path'][len('file://'):]
        for plugin_class in get_plugins_from_file(filename):
            output[cast('BasePlugin', plugin_class).secret_type] = plugin_class

    return output


def get_plugins_from_file(filename: str) -> Generator[type[BasePlugin], None, None]:
    yield from get_plugins_from_module(import_file_as_module(filename))


def get_plugins_from_module(module: ModuleType) -> Generator[type[BasePlugin], None, None]:
    for plugin_class in import_types_from_module(module, filter=lambda x: not _is_valid_plugin(x)):
        yield cast('type[BasePlugin]', plugin_class)


def _is_valid_plugin(attribute: Any) -> bool:
    return (
        inspect.isclass(attribute)
        and issubclass(attribute, BasePlugin)
        # Heuristic to determine abstract classes
        and 'secret_type' not in attribute.__abstractmethods__
    )
