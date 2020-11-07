import inspect
from abc import abstractproperty
from functools import lru_cache
from typing import Any
from typing import Dict
from typing import Type
from typing import TypeVar

from ... import plugins
from ...plugins.base import BasePlugin
from ...util.importlib import import_types_from_module


Plugin = TypeVar('Plugin', bound=BasePlugin)


@lru_cache(maxsize=1)
def get_mapping_from_secret_type_to_class() -> Dict[str, Type[Plugin]]:
    # TODO: custom_plugin_paths
    output = {}
    for plugin_class in import_types_from_module(
        plugins,
        filter=lambda x: not _is_valid_plugin(x),
    ):
        output[plugin_class.secret_type] = plugin_class

    return output


def _is_valid_plugin(attribute: Any) -> bool:
    return (
        inspect.isclass(attribute)
        and issubclass(attribute, BasePlugin)
        # Heuristic to determine abstract classes
        and not isinstance(attribute.secret_type, abstractproperty)
    )
