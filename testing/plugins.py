import re
from contextlib import contextmanager
from typing import Any
from typing import Generator

from detect_secrets.core.plugins import Plugin
from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class
from detect_secrets.plugins.base import RegexBasedDetector


@contextmanager
def register_plugin(plugin: Plugin) -> Generator[None, None, None]:
    def get_instance(*args: Any, **kwargs: Any) -> Plugin:
        # NOTE: We need this, because the initialization process auto-fills in arguments
        # to the classname. However, we already have an instance, so it doesn't matter.
        return plugin

    try:
        get_mapping_from_secret_type_to_class()[plugin.secret_type] = get_instance  # type: ignore
        yield
    finally:
        # On next run, it should re-initialize to base state.
        get_mapping_from_secret_type_to_class.cache_clear()


class HippoDetector(RegexBasedDetector):
    """Scans for hippos."""
    secret_type = 'Hippo'

    denylist = (
        re.compile(
            r'(hippo)',
            re.IGNORECASE,
        ),
    )
