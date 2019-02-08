from __future__ import absolute_import

import pytest

from detect_secrets.plugins.base import BasePlugin


def test_fails_if_no_secret_type_defined():
    class MockPlugin(BasePlugin):  # pragma: no cover

        def _analyze_string(self, *args, **kwargs):
            pass

        def secret_generator(self, *args, **kwargs):
            pass

    with pytest.raises(ValueError):
        MockPlugin()
