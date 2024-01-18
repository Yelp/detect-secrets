import pytest
from detect_secrets.plugins.telegram_token import TekegramTokenDetector

class TestTelegramTokenDetector:
    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('6741529203:AAE17nfyMEuzRf4LrOXokArH4HzTt2opO2s', True),
            ('6151527a03:AAE17nfrMEfzRf4KrOXotArH4HzTt2opO2s', False),
            ('6910343172:AAGiAHt7SPe_rryV9AVK48-IBisa-Zq-azc', True),
            ('6990343172:AAGiAHt7SPe~rryV9AVK48-IBisa-Zq-azc', False),
            ('database', False),
        ],
    )

    def test_analyze(self, payload, should_flag):
        logic = GitHubTokenDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)
