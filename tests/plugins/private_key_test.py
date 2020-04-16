import pytest

from detect_secrets.plugins.private_key import PrivateKeyDetector
from testing.mocks import mock_file_object


class TestPrivateKeyDetector:

    @pytest.mark.parametrize(
        'file_content',
        [
            (
                '-----BEGIN RSA PRIVATE KEY-----\n'
                'super secret private key here\n'
                '-----END RSA PRIVATE KEY-----'
            ),
            (
                'some text here\n'
                '-----BEGIN PRIVATE KEY-----\n'
                'yabba dabba doo'
            ),
        ],
    )
    def test_analyze(self, file_content):
        logic = PrivateKeyDetector()

        f = mock_file_object(file_content)
        output = logic.analyze(f, 'mock_filename')
        assert len(output) == 1
        for potential_secret in output:
            assert 'mock_filename' == potential_secret.filename
