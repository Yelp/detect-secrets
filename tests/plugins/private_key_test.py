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
        assert 'mock_filename' in logic.analyze(f, 'mock_filename')
