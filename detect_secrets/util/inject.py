from typing import Any
from typing import Callable
from typing import Tuple

from ..types import SelfAwareCallable


def inject_variables_into_function(func: SelfAwareCallable, **kwargs: Any) -> Any:
    variables_to_inject = set(kwargs.keys())
    values = {
        key: kwargs[key]
        for key in (variables_to_inject & func.injectable_variables)
    }

    if set(values.keys()) != func.injectable_variables:
        return

    return func(**values)


def get_injectable_variables(func: Callable) -> Tuple[str, ...]:
    """
    The easiest way to understand this is to see it as an example:
        >>> def func(a, b=1, *args, c, d=2, **kwargs):
        ...     e = 5
        >>>
        >>> print(func.__code__.co_varnames)
        ('a', 'b', 'c', 'd', 'args', 'kwargs', 'e')
        >>> print(func.__code__.co_argcount)    # `a` and `b`
        2
        >>> print(func.__code__.co_kwonlyargcount)  # `c` and `d`
        2
    """
    variable_names = func.__code__.co_varnames
    arg_count = func.__code__.co_argcount + func.__code__.co_kwonlyargcount

    return variable_names[:arg_count]
