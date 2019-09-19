from __future__ import absolute_import

import pytest

from detect_secrets.plugins.common import filters


class TestIsSequentialString:
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
        assert filters._is_sequential_string(secret)

    @pytest.mark.parametrize(
        'secret',
        (
            'BEEF1234',
        ),
    )
    def test_failure(self, secret):
        assert not filters._is_sequential_string(secret)
