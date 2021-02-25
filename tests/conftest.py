import contextlib
import warnings
from unittest import mock

import pytest
import responses

import detect_secrets
from detect_secrets import filters
from detect_secrets import settings
from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class
from detect_secrets.util.importlib import get_modules_from_package
from testing.mocks import MockLogWrapper


@pytest.fixture(autouse=True)
def clear_cache():
    # This is also probably too aggressive, but test pollution is tough to debug.
    # So let's just trade off slightly longer test runs for shorter developer time to debug
    # test pollution issues.
    get_mapping_from_secret_type_to_class.cache_clear()

    settings.get_settings().clear()
    settings.cache_bust()

    # This is probably too aggressive, but it saves us from remembering to do this every
    # time we add a filter.
    for module_name in dir(filters):
        if module_name.startswith('_'):
            continue

        module = getattr(filters, module_name)
        for name in dir(module):
            try:
                getattr(module, name).cache_clear()
            except AttributeError:
                pass


@pytest.fixture(autouse=True)
def mock_log():
    log = MockLogWrapper()
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
    mock_log.warning = lambda x: MockLogWrapper.warning(mock_log, x)
    yield mock_log


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


@pytest.fixture(autouse=True)
def mocked_requests():
    # With default verified secrets, we don't want to be making API calls during tests.
    with responses.RequestsMock() as rsps:
        yield rsps


@pytest.fixture(autouse=True)
def prevent_clear_screen():
    with mock.patch('detect_secrets.audit.io.clear_screen'):
        yield
