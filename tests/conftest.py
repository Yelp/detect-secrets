import contextlib
import pkgutil
from unittest import mock

import pytest

import detect_secrets
from detect_secrets.core.secrets_collection import get_filters
from detect_secrets.core.secrets_collection import get_plugins
from detect_secrets.settings import get_settings


@pytest.fixture(autouse=True)
def clear_cache():
    get_settings.cache_clear()
    get_filters.cache_clear()
    get_plugins.cache_clear()


@pytest.fixture(autouse=True)
def mock_log():
    log = mock.Mock()
    with contextlib.ExitStack() as ctx_stack:
        for ctx in [
            mock.patch(f'{module}.log', log, create=True)
            for _, module, is_package in pkgutil.walk_packages(
                path=detect_secrets.__path__, prefix=f'{detect_secrets.__name__}.',
            )
            if not is_package
        ]:
            ctx_stack.enter_context(ctx)

        yield log
