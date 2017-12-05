#!/usr/bin/python
from __future__ import absolute_import

import unittest

from detect_secrets.core.potential_secret import PotentialSecret


class PotentialSecretTest(unittest.TestCase):

    def test_equality(self):
        A = PotentialSecret('type', 'filename', 1, 'secret')
        B = PotentialSecret('type', 'filename', 2, 'secret')
        assert A == B

        A = PotentialSecret('typeA', 'filename', 1, 'secret')
        B = PotentialSecret('typeB', 'filename', 1, 'secret')
        assert A != B

        A = PotentialSecret('type', 'filename', 1, 'secretA')
        B = PotentialSecret('type', 'filename', 1, 'secretB')
        assert A != B

    def test_secret_storage(self):
        secret = PotentialSecret('type', 'filename', 1, 'secret')
        assert secret.secret_hash != 'secret'
