import inspect
import sys
from functools import lru_cache
from typing import Any
from typing import Iterable
from typing import TypeVar

from ..util.importlib import import_types_from_package
from .base import BaseTransformer
from .exceptions import ParsingError    # noqa: F401


Transformer = TypeVar('Transformer', bound=BaseTransformer)


@lru_cache(maxsize=1)
def get_transformers() -> Iterable[Transformer]:
    return [
        item()
        for item in import_types_from_package(
            sys.modules[__name__],
            filter=lambda x: not _is_valid_transformer(x),
        )
    ]


def _is_valid_transformer(attribute: Any) -> bool:
    return (
        inspect.isclass(attribute)
        and issubclass(attribute, BaseTransformer)
        and attribute.__name__ != 'BaseTransformer'
    )
