import pytest

from detect_secrets.settings import get_settings


@pytest.fixture(autouse=True)
def clear_cache():
    get_settings.cache_clear()
