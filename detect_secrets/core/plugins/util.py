import inspect
import pkgutil
from abc import abstractproperty
from functools import lru_cache
from importlib import import_module
from types import ModuleType
from typing import Dict
from typing import Type
from typing import TypeVar

from ... import plugins
from ...plugins.base import BasePlugin


Plugin = TypeVar('Plugin', bound=BasePlugin)


@lru_cache(maxsize=1)
def get_mapping_from_secret_type_to_class() -> Dict[str, Type[Plugin]]:
    # TODO: custom_plugin_paths
    modules = [
        module
        for _, module, is_package in pkgutil.walk_packages(
            plugins.__path__, prefix=f'{plugins.__name__}.',    # type: ignore  # mypy issue #1422
        )
        if not is_package
    ]

    output = {}

    for module_path in modules:
        module = import_module(module_path)
        attributes = [
            getattr(module, attribute)
            for attribute in dir(module)
            if (
                not attribute.startswith('_')
                and _is_valid_plugin(module, attribute)
            )
        ]

        for attribute in attributes:
            output[attribute.secret_type] = attribute

    return output


def _is_valid_plugin(module: ModuleType, name: str) -> bool:
    attribute = getattr(module, name)
    return (
        inspect.isclass(attribute)
        and issubclass(attribute, BasePlugin)
        # Heuristic to determine abstract classes
        and not isinstance(attribute.secret_type, abstractproperty)
    )
