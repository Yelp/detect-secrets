import pytest

from detect_secrets.plugins.stripe import StripeDetector
from testing.mocks import mock_file_object


class TestStripeKeyDetector:

    @pytest.mark.parametrize(
        'file_content,should_flag',
        [
            (
                'sk_live_ReTllpYQYfIZu2Jnf2lAPFjD',
                True,
            ),
            (
                'rk_live_5TcWfjKmJgpql9hjpRnwRXbT',
                True,
            ),
            (
                'pk_live_j5krY8XTgIcDaHDb3YrsAfCl',
                False,
            ),
            (
                'sk_live_',
                False,
            ),
        ],
    )
    def test_analyze(self, file_content, should_flag):
        logic = StripeDetector()

        f = mock_file_object(file_content)
        output = logic.analyze(f, 'mock_filename')
        assert len(output) == (1 if should_flag else 0)
        for potential_secret in output:
            assert 'mock_filename' == potential_secret.filename
