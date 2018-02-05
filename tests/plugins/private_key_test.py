#!/usr/bin/python
from __future__ import absolute_import

import unittest

from detect_secrets.plugins.private_key import PrivateKeyDetector
from tests.util.file_util import create_file_object_from_string


class PrivateKeyDetectorTest(unittest.TestCase):

    def setUp(self):
        self.logic = PrivateKeyDetector()

    def test_analyze(self):
        file_content = (
            '-----BEGIN RSA PRIVATE KEY-----'
            'super secret private key here'
            '-----END RSA PRIVATE KEY-----'
        )

        f = create_file_object_from_string(file_content)
        assert 'mock_filename' in self.logic.analyze(f, 'mock_filename')
