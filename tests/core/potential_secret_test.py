import pytest

from testing.factories import potential_secret_factory


class TestPotentialSecret:

    @pytest.mark.parametrize(
        'a, b, is_equal',
        [
            (
                potential_secret_factory(lineno=1),
                potential_secret_factory(lineno=2),
                True,
            ),
            (
                potential_secret_factory(type_='A'),
                potential_secret_factory(type_='B'),
                False,
            ),
            (
                potential_secret_factory(secret='A'),
                potential_secret_factory(secret='B'),
                False,
            ),
        ],
    )
    def test_equality(self, a, b, is_equal):
        assert (a == b) is is_equal

        # As a sanity check that it works both ways
        assert (a != b) is not is_equal

    def test_secret_storage(self):
        secret = potential_secret_factory(secret='secret')
        assert secret.secret_hash != 'secret'

    def test_json(self):
        secret = potential_secret_factory(secret='blah')
        for value in secret.json().values():
            assert value != 'blah'
