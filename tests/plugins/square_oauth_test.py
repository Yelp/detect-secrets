import pytest

from detect_secrets.plugins.square_oauth import SquareOAuthDetector


class TestSquareOauthDetector:

    @pytest.mark.parametrize(
        'payload',
        (
            'square_oauth = sq0csp-ABCDEFGHIJK_LMNOPQRSTUVWXYZ-0123456789\\abcd',
        ),
    )
    def test_analyze(self, payload):
        logic = SquareOAuthDetector()
        assert logic.analyze_line(filename='mock_filename', line=payload)
