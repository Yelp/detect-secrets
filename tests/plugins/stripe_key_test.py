import pytest

from detect_secrets.plugins.stripe import StripeDetector


class TestStripeKeyDetector:

    @pytest.mark.parametrize(
        'line,should_flag',
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
    def test_analyze(self, line, should_flag):
        logic = StripeDetector()

        output = logic.analyze_line(filename='mock_filename', line=line)
        assert len(output) == (1 if should_flag else 0)
