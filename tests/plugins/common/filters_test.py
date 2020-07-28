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
        assert filters.is_sequential_string(secret)

    @pytest.mark.parametrize(
        'secret',
        (
            'BEEF1234',
        ),
    )
    def test_failure(self, secret):
        assert not filters.is_sequential_string(secret)


class TestIsLikelyIdString:
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


class TestIsPotentialUuid:
    @pytest.mark.parametrize(
        'secret',
        [
            '3636dd46-ea21-11e9-81b4-2a2ae2dbcce4',  # uuid1
            '97fb0431-46ac-41df-9ef9-1a18545ce2a0',  # uuid4
            'prefix-3636dd46-ea21-11e9-81b4-2a2ae2dbcce4-suffix',  # uuid in middle of string
        ],
    )
    def test_success(self, secret):
        assert filters.is_potential_uuid(secret)
