from typing import Generator

import pytest
import requests

from detect_secrets.constants import VerifiedResult
from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class
from detect_secrets.plugins.base import BasePlugin
from detect_secrets.settings import get_settings
from detect_secrets.util.code_snippet import CodeSnippet
from detect_secrets.util.code_snippet import get_code_snippet


def test_ensure_all_plugins_have_unique_secret_types():
    secret_types = set()
    for plugin_type in get_mapping_from_secret_type_to_class().values():
        secret_types.add(plugin_type.secret_type)

    assert len(secret_types) == len(get_mapping_from_secret_type_to_class())


class MockPlugin(BasePlugin):
    secret_type = 'MockPlugin'

    def __init__(self, verify_result: VerifiedResult):
        self.verify_result = verify_result
        self.verify_call_count = 0

    def verify(self, secret: str, context: CodeSnippet) -> VerifiedResult:
        self.verify_call_count += 1
        return self.verify_result

    def analyze_string(self, string: str) -> Generator[str, None, None]:
        yield string


class MockExceptionRaisingPlugin(BasePlugin):
    secret_type = 'MockExceptionRaisingPlugin'

    def analyze_string(self, string: str) -> Generator[str, None, None]:
        yield string

    def verify(self, secret: str, context: CodeSnippet):
        raise requests.exceptions.Timeout


class TestAnalyzeLine():
    def setup(self):
        self.line = 'some-secret'
        self.filename = 'secrets.py'
        self.context = get_code_snippet(lines=[self.line], line_number=1)

    @pytest.mark.parametrize(
        'verified_result ,is_verified',
        [
            (VerifiedResult.UNVERIFIED, False),
            (VerifiedResult.VERIFIED_FALSE, False),
            (VerifiedResult.VERIFIED_TRUE, True),
        ],
    )
    def test_potential_secret_constructed_correctly(self, verified_result, is_verified):
        self._enable_filter()
        plugin = MockPlugin(verified_result)
        output = plugin.analyze_line(
            filename=self.filename,
            line=self.line,
            line_number=1,
            context=self.context,
        )
        secret = list(output)[0]
        assert secret.secret_value == self.line
        assert secret.type == plugin.secret_type
        assert secret.filename == self.filename
        assert secret.line_number == 1
        assert secret.is_verified == is_verified

    def test_no_verification_call_if_verification_filter_is_disabled(self):
        self._disable_filter()
        plugin = MockPlugin(VerifiedResult.VERIFIED_TRUE)
        output = plugin.analyze_line(
            filename=self.filename,
            line=self.line,
            line_number=1,
            context=self.context,
        )
        secret = list(output)[0]
        assert secret.is_verified is False
        assert plugin.verify_call_count == 0

    def test_handle_verify_exception_gracefully(self):
        self._enable_filter()
        plugin = MockExceptionRaisingPlugin()
        output = plugin.analyze_line(
            filename=self.filename,
            line=self.line,
            line_number=1,
            context=self.context,
        )
        secret = list(output)[0]
        assert secret.is_verified is False

    def _enable_filter(self):
        get_settings().filters[
            'detect_secrets.filters.common.is_ignored_due_to_verification_policies'
        ] = {
            'min_value': 0,
        }

    def _disable_filter(self):
        get_settings().disable_filters(
            'detect_secrets.filters.common.is_ignored_due_to_verification_policies',
        )
