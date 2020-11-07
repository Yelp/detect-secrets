import pkgutil
from importlib import import_module
from types import ModuleType
from typing import Any
from typing import Callable
from typing import Iterable
from typing import Type


def import_types_from_module(
    root: ModuleType,
    filter: Callable[[Any], bool],
) -> Iterable[Type]:
    output = []
    modules = _get_modules_from_package(root)

    for module_path in modules:
        module = import_module(module_path)
        for name in dir(module):
            if name.startswith('_'):
                continue

            attribute = getattr(module, name)
            if filter(attribute):
                continue

            output.append(attribute)

    return output


def import_modules_from_package(
    root: ModuleType,
    filter: Callable[[str], bool],
) -> Iterable[ModuleType]:
    output = []
    modules = _get_modules_from_package(root)

    # NOTE: It should be auto-sorted, but let's just do it for sanity sake.
    for module_path in sorted(modules):
        if filter(module_path):
            continue

        output.append(import_module(module_path))

    return output


def _get_modules_from_package(root: ModuleType) -> Iterable[str]:
    return [
        module
        for _, module, is_package in pkgutil.walk_packages(
            root.__path__, prefix=f'{root.__name__}.',    # type: ignore  # mypy issue #1422
        )
        if not is_package
    ]
