from unittest import mock

import pytest

from detect_secrets.core import scan
from detect_secrets.settings import get_plugins
from detect_secrets.settings import transient_settings
from testing.mocks import mock_named_temporary_file

AWS_LINE = 'aws_access_key_id = "AKIAIOSFODNN7ABCDEFG"\n'
PLAIN_LINES = 'def add(a, b):\n    return a + b\n'


def scan_content(content: str, prevalidation: bool):
    with mock.patch.object(scan, '_PREVALIDATION_ENABLED', prevalidation), \
            mock_named_temporary_file(suffix='.py') as f:
        f.write(content.encode())
        f.seek(0)
        return sorted((s.type, s.line_number, s.secret_hash) for s in scan.scan_file(f.name))


class TestPrevalidation:
    @staticmethod
    @pytest.mark.parametrize('content', [AWS_LINE, PLAIN_LINES, PLAIN_LINES + AWS_LINE])
    def test_same_findings_with_and_without_prevalidation(content):
        assert scan_content(content, prevalidation=True) == scan_content(content, prevalidation=False)

    @staticmethod
    def test_finds_secret_with_prevalidation_enabled():
        assert scan_content(PLAIN_LINES + AWS_LINE, prevalidation=True)

    @staticmethod
    def test_skips_regex_plugin_whose_literals_are_absent():
        aws, private_key = sorted(get_plugins(), key=lambda p: type(p).__name__)
        document = PLAIN_LINES.lower()
        assert not scan._passes_prevalidation(aws, document)
        assert not scan._passes_prevalidation(private_key, document)
        assert scan._passes_prevalidation(aws, AWS_LINE.lower())

    @staticmethod
    def test_plugin_level_prevalidate_hook_is_respected():
        plugin = mock.Mock()
        plugin.prevalidate.return_value = False
        assert not scan._passes_prevalidation(plugin, 'anything')
        plugin.prevalidate.assert_called_once_with('anything')

    @staticmethod
    def test_non_regex_plugins_always_run():
        class EntropyLikePlugin:
            pass

        assert scan._passes_prevalidation(EntropyLikePlugin(), 'anything')


@pytest.fixture(autouse=True)
def configure_plugins():
    with transient_settings({
        'plugins_used': [
            {'name': 'AWSKeyDetector'},
            {'name': 'PrivateKeyDetector'},
        ],
    }):
        scan._plugin_requirements.clear()
        yield
        scan._plugin_requirements.clear()
