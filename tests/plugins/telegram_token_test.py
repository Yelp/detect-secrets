import pytest

from detect_secrets.plugins.telegram_token import TelegramBotTokenDetector


class TestTelegramTokenDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('bot110201543:AAHdqTcvCH1vGWJxfSe1ofSAs0K5PALDsaw', False),
            ('110201543:AAHdqTcvCH1vGWJxfSe1ofSAs0K5PALDsaw', True),
            ('7213808860:AAH1bjqpKKW3maRSPAxzIU-0v6xNuq2-NjM', True),
            ('foo:AAH1bjqpKKW3maRSPAxzIU-0v6xNuq2-NjM', False),
            ('foo', False),
            ('arn:aws:sns:aaa:111122223333:aaaaaaaaaaaaaaaaaaassssssddddddddddddd', False),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = TelegramBotTokenDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)

        assert len(output) == int(should_flag)
