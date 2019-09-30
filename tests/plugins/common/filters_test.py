from __future__ import absolute_import

import pytest

from detect_secrets.plugins.common import filters


class TestIsSequentialString(object):
    @pytest.mark.parametrize(
        'secret',
        (
            # ASCII sequence
            'ABCDEF',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ',

            # Number sequences
            '0123456789',
            '1234567890',

            # Alphanumeric sequences
            'abcdefghijklmnopqrstuvwxyz0123456789',
            '0123456789abcdefghijklmnopqrstuvwxyz',

            # Hex sequences
            '0123456789abcdef',
            'abcdef0123456789',

            # Base64 sequences
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
            '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/',
        ),
    )
    def test_success(self, secret):
        assert filters.is_sequential_string(secret)

    @pytest.mark.parametrize(
        'secret',
        (
            'BEEF1234',
        ),
    )
    def test_failure(self, secret):
        assert not filters.is_sequential_string(secret)


class TestIsLikelyIdString(object):
    @pytest.mark.parametrize(
        'secret, line',
        [
            ('RANDOM_STRING', 'id: RANDOM_STRING'),
            ('RANDOM_STRING', 'id=RANDOM_STRING'),
            ('RANDOM_STRING', 'id = RANDOM_STRING'),
            ('RANDOM_STRING', 'myid: RANDOM_STRING'),
            ('RANDOM_STRING', 'myid=RANDOM_STRING'),
            ('RANDOM_STRING', 'myid = RANDOM_STRING'),
        ],
    )
    def test_success(self, secret, line):
        assert filters.is_likely_id_string(secret, line)

    @pytest.mark.parametrize(
        'secret, line',
        [
            # the word hidden has the word id in it, but lets
            # not mark that as an id string
            ('RANDOM_STRING', 'hidden_secret: RANDOM_STRING'),
            ('RANDOM_STRING', 'hidden_secret=RANDOM_STRING'),
            ('RANDOM_STRING', 'hidden_secret = RANDOM_STRING'),

            # fail silently if the secret isn't even on the line
            ('SOME_RANDOM_STRING', 'id: SOME_OTHER_RANDOM_STRING'),
        ],
    )
    def test_failure(self, secret, line):
        assert not filters.is_likely_id_string(secret, line)
