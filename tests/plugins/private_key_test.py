import pytest

from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.settings import transient_settings
from testing.mocks import mock_named_temporary_file


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
def test_basic(file_content):
    with mock_named_temporary_file() as f:
        f.write(file_content.encode())
        f.seek(0)

        secrets = SecretsCollection()
        secrets.scan_file(f.name)

    assert len(list(secrets)) == 1


@pytest.fixture(autouse=True)
def configure_plugins():
    with transient_settings({
        'plugins_used': [{'name': 'PrivateKeyDetector'}],
    }):
        yield
