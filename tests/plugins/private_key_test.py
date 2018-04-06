from __future__ import absolute_import

from detect_secrets.plugins.private_key import PrivateKeyDetector
from tests.util.file_util import create_file_object_from_string


class TestPrivateKeyDetector(object):

    def test_analyze(self):
        logic = PrivateKeyDetector()

        file_content = (
            '-----BEGIN RSA PRIVATE KEY-----'
            'super secret private key here'
            '-----END RSA PRIVATE KEY-----'
        )

        f = create_file_object_from_string(file_content)
        output = logic.analyze(f, 'mock_filename')
        assert len(output) == 1
        for potential_secret in output:
            assert 'mock_filename' == potential_secret.filename
