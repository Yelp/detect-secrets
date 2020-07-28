from contextlib import contextmanager

import mock
import pytest

from detect_secrets.core.constants import VerifiedResult
from detect_secrets.plugins.base import BasePlugin
from testing.factories import potential_secret_factory
from testing.mocks import mock_file_object


@pytest.mark.parametrize(
    'name, expected',
    (
        ('HexHighEntropyString', 'no-hex-high-entropy-string-scan'),
        ('KeywordDetector', 'no-keyword-scan'),
        ('PrivateKeyDetector', 'no-private-key-scan'),
    ),
)
def test_disable_flag_text(name, expected):
    class MockPlugin(BasePlugin):
        @property
        def secret_type(self):      # pragma: no cover
            return ''

    MockPlugin.__name__ = str(name)

    assert MockPlugin.disable_flag_text == expected


class TestVerify:
    @pytest.mark.parametrize(
        'result, output',
        (
            (
                VerifiedResult.UNVERIFIED,
                'True  (unverified)',
            ),
            (
                VerifiedResult.VERIFIED_FALSE,
                'False (verified)',
            ),
            (
                VerifiedResult.VERIFIED_TRUE,
                'True  (verified)',
            ),
        ),
    )
    def test_adhoc_scan_values(self, result, output):
        with self.create_test_plugin(result) as plugin:
            assert plugin.adhoc_scan('test value') == output

    def test_adhoc_scan_should_abide_by_no_verify_flag(self):
        with self.create_test_plugin(VerifiedResult.VERIFIED_TRUE) as plugin:
            plugin.should_verify = False

        assert plugin.adhoc_scan('test value') == 'True'

    def test_analyze_verified_false_ignores_value(self):
        with self.create_test_plugin(VerifiedResult.VERIFIED_FALSE) as plugin:
            file = mock_file_object('does not matter')
            result = plugin.analyze(file, 'does not matter')

        assert len(result) == 0

    def test_analyze_verified_true_adds_intel(self):
        with self.create_test_plugin(VerifiedResult.VERIFIED_TRUE) as plugin:
            file = mock_file_object('does not matter')
            result = plugin.analyze(file, 'does not matter')

        assert list(result.keys())[0].is_verified

    def test_analyze_unverified_stays_the_same(self):
        with self.create_test_plugin(VerifiedResult.UNVERIFIED) as plugin:
            file = mock_file_object('does not matter')
            result = plugin.analyze(file, 'does not matter')

        assert not list(result.keys())[0].is_verified

    def test_analyze_should_abide_by_no_verify_flag(self):
        with self.create_test_plugin(VerifiedResult.VERIFIED_FALSE) as plugin:
            plugin.should_verify = False

            file = mock_file_object('does not matter')
            result = plugin.analyze(file, 'does not matter')

        # If it is verified, this value should be 0.
        assert len(result) == 1

    @contextmanager
    def create_test_plugin(self, result):
        """
        :type result: VerifiedResult
        """
        class MockPlugin(BasePlugin):  # pragma: no cover
            secret_type = 'test_verify'

            def analyze_string_content(self, *args, **kwargs):
                secret = potential_secret_factory()
                return {
                    secret: secret,
                }

            def secret_generator(self, *args, **kwargs):
                pass

            def verify(self, *args, **kwargs):
                return result

        with mock.patch(
            'detect_secrets.plugins.base.CodeSnippetHighlighter',
            autospec=True,
        ) as mock_snippet:
            plugin = MockPlugin()
            plugin.should_verify = True

            mock_snippet().get_code_snippet.return_value = ''

            yield plugin
