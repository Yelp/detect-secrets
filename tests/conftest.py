import contextlib
import warnings
from unittest import mock

import pytest

import detect_secrets
from detect_secrets import settings
from detect_secrets.util.importlib import get_modules_from_package


@pytest.fixture(autouse=True)
def clear_cache():
    settings.cache_bust()


@pytest.fixture(autouse=True)
def mock_log():
    log = mock.Mock()
    log.warning = warnings.warn     # keep warnings around for easier debugging

    with contextlib.ExitStack() as ctx_stack:
        for ctx in [
            mock.patch(f'{module}.log', log, create=True)
            for module in get_modules_from_package(detect_secrets)
        ]:
            ctx_stack.enter_context(ctx)

        yield log


@pytest.fixture
def mock_log_warning(mock_log):
    mock_log.warning = mock.Mock()
    yield mock_log.warning


@pytest.fixture(autouse=True)
def prevent_color():
    def uncolor(text, color):
        return text

    with contextlib.ExitStack() as ctx_stack:
        for ctx in [
            mock.patch(f'{module}.colorize', uncolor, create=True)
            for module in get_modules_from_package(detect_secrets)
        ]:
            ctx_stack.enter_context(ctx)

        yield
