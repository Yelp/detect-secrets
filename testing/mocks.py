"""This is a collection of utility functions for easier, DRY testing."""
import io
from collections import defaultdict
from contextlib import contextmanager
from types import ModuleType
from typing import Any
from typing import Optional
from unittest import mock


def mock_file_object(string: str):
    return io.StringIO(string)


class PrinterShim:
    def __init__(self) -> None:
        self.clear()

    def add(self, message: str, *args: Any, **kwargs: Any) -> None:
        self.message += str(message) + '\n'

    def clear(self) -> None:
        self.message = ''


@contextmanager
def mock_printer(module: ModuleType, shim: Optional[PrinterShim] = None):
    if not shim:
        shim = PrinterShim()

    with mock.patch.object(module, 'print', shim.add):
        yield shim


class MockLogWrapper:
    """This is used to check what is being logged."""

    def __init__(self):
        self.messages = defaultdict(str)

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
