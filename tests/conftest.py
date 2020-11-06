import contextlib
import pkgutil
from unittest import mock

import pytest

import detect_secrets
from detect_secrets import settings


@pytest.fixture(autouse=True)
def clear_cache():
    settings.cache_bust()


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
