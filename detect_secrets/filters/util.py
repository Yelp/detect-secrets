import inspect


def get_caller_path(offset: int = 0) -> str:
    """
    This is a utility function to get the caller's fully qualified python import path,
    so that it can be used to index into the global settings object. It is highly
    recommended to cache the response to this (for performance reasons), as such:

    >>> @lru_cache(maxsize=1)
    ... def _get_specific_caller_path() -> str:
    ...     return get_caller_path(offset=1)

    For a deeper dive into why this performance matters, check out
    https://stackoverflow.com/a/17366561/13340678, and estimate how many secrets you will
    need to filter out (and thereby, invoke this function for)

    :raises: IndexError
    """
    stack = inspect.stack()
    frame_info = stack[1 + offset]      # +1 because we don't want the current frame.

    module_path = frame_info.frame.f_globals['__name__']
    function_name = frame_info.function
    return f'{module_path}.{function_name}'
