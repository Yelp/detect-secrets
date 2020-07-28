import pytest

from detect_secrets.plugins.twilio import TwilioKeyDetector


class TestTwilioKeyDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            (
                'SKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
                True,
            ),
            (
                'ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
                True,
            ),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = TwilioKeyDetector()
        output = logic.analyze_line(payload, 1, 'mock_filename')
        assert output
