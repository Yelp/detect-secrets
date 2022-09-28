"""This is a collection of utility functions for easier, DRY testing."""
import io
import os
import tempfile
from collections import defaultdict
from contextlib import contextmanager
from types import ModuleType
from typing import Any
from typing import Dict
from typing import Generator
from typing import IO
from typing import Iterator
from typing import Optional
from unittest import mock


def mock_file_object(string: str) -> IO:
    return io.StringIO(string)


class PrinterShim:
    def __init__(self) -> None:
        self.clear()

    def add(self, message: str, *args: Any, **kwargs: Any) -> None:
        self.message += str(message) + '\n'

    def clear(self) -> None:
        self.message = ''


@contextmanager
def mock_printer(
    module: ModuleType,
    shim: Optional[PrinterShim] = None,
) -> Generator[PrinterShim, None, None]:
    if not shim:
        shim = PrinterShim()

    with mock.patch.object(module, 'print', shim.add):
        yield shim


class MockLogWrapper:
    """This is used to check what is being logged."""

    def __init__(self) -> None:
        self.messages: Dict[str, str] = defaultdict(str)

    def error(self, message: str, *args: Any) -> None:
        self.messages['error'] += (str(message) + '\n') % args

    @property
    def error_messages(self) -> str:        # pragma: no cover
        return self.messages['error']

    def warning(self, message: str, *args: Any) -> None:
        self.messages['warning'] += (str(message) + '\n') % args

    @property
    def warning_messages(self) -> str:      # pragma: no cover
        return self.messages['warning']

    def info(self, message: str, *args: Any) -> None:
        self.messages['info'] += (str(message) + '\n') % args

    @property
    def info_messages(self) -> str:         # pragma: no cover
        return self.messages['info']

    def debug(self, message: str, *args: Any) -> None:
        self.messages['debug'] += (str(message) + '\n') % args

    @property
    def debug_messages(self) -> str:        # pragma: no cover
        return self.messages['debug']


@contextmanager
def disable_gibberish_filter() -> Iterator[None]:
    """
    Unfortunately, we can't just use `Settings.disable_filters`, since `parse_args` is
    the function that *enables* this filter. Therefore, for test cases that test through
    the `main` function flow, we can't disable the filter before the function call.

    However, since this only happens in test environments, we can just mock it out.
    """
    with mock.patch(
        'detect_secrets.filters.gibberish.is_feature_enabled',
        return_value=False,
    ):
        yield


@contextmanager
def mock_named_temporary_file(
    mode: str = 'w+b', dir: str = None,
    suffix: str = None, prefix: str = None,
) -> Iterator[IO[Any]]:
    """
    Used to create a mock temporary named file to write baseline files and secret files in
    test. To avoid platform differences on how "NamedTemporaryFile" operates, we will perform
    the creation and cleanup of the temporary file here.
    """
    with tempfile.NamedTemporaryFile(
        mode=mode, dir=dir, suffix=suffix, prefix=prefix, delete=False,
    ) as f:
        yield f

    f.close()
    os.unlink(f.name)
