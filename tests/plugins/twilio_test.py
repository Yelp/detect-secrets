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
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert output
