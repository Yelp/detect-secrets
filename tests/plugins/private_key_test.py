import pytest
import json

from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.settings import transient_settings
from testing.mocks import mock_named_temporary_file


@pytest.mark.parametrize(
    'file_content, secrets_amount, expected_secret',
    [
        (
            json.dumps(
                '-----BEGIN RSA PRIVATE KEY-----\n'
                'c3VwZXIgZHVwZXIgc2VjcmV0IHBhc3N3b3JkLCBzdXBlciBkdXBlciBzZ\n'
                'WNyZXQgcGFzc3dvcmQhMTIzNCMkJQpzdXBlciBkdXBlciBzZWNyZXQgcGFzc3'
                'dvcmQsIHN1cGVyIGR1cGVyIHNlY3JldCBwYXNzd29yZCExMjM0IyQlCgo=\n'
                '-----END RSA PRIVATE KEY-----',
            ),
            1,
            '\\nc3VwZXIgZHVwZXIgc2VjcmV0IHBhc3N3b3JkLCBzdXBlciBkdXBlciBzZ\\n'
            'WNyZXQgcGFzc3dvcmQhMTIzNCMkJQpzdXBlciBkdXB'
            'lciBzZWNyZXQgcGFzc3dvcmQsIHN1cGVyIGR1cGVyIHNlY3JldCBwYXNzd29yZCExMjM0IyQlCgo=',
        ),
        (
            'some text here\n'
            '-----BEGIN PRIVATE KEY-----\n'
            'c3VwZXIgZHVwZXIgc2VjcmV0IHBhc3N3b3JkLCBzdXBlciBkdXBlciBzZWNyZXQgcGFzc3'
            'dvcmQhMTIzNCMkJQpzdXBlciBkdXBlciBzZWNyZXQgcGFzc3dvcmQsIHN1cGVyIGR1cGVy'
            'IHNlY3JldCBwYXNzd29yZCExMjM0IyQlCgo=\n'
            '-----END PRIVATE KEY-----',
            1,
            'BEGIN PRIVATE KEY-----',
        ),
        (
            'some text here\n'
            'PuTTY-User-Key-File-2\n'
            'secret key',
            1,
            'PuTTY-User-Key-File-2',
        ),
    ],
)
def test_basic(file_content, secrets_amount, expected_secret):
    with mock_named_temporary_file() as f:
        f.write(file_content.encode())
        f.seek(0)

        secrets = SecretsCollection()
        secrets.scan_file(f.name)

    temp_file = list(secrets.files)[0]
    assert len(list(secrets)) == secrets_amount
    assert list(secrets.data[temp_file])[0].secret_value == expected_secret


@pytest.fixture(autouse=True)
def configure_plugins():
    with transient_settings({
        'plugins_used': [{'name': 'PrivateKeyDetector'}],
    }):
        yield
