from __future__ import absolute_import

import pytest

from detect_secrets.plugins.common import filters


class TestIsSequentialString:
    # TODO: More tests should be had.

    @pytest.mark.parametrize(
        'secret',
        (
            'ABCDEF',

            # Number sequences
            '0123456789',
            '1234567890',
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
