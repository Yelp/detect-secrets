import pytest

from detect_secrets.plugins.aiven_token import AivenTokenDetector


class TestAivenTokenDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('AVNS_4Yt6Gdnjcs8ivIlYSFU', True),
            ('AVNS_D0j9bUsCyQ3s67T', True),
            ('AVNS_LaGqz39AC', True),
            ('AVNS_RaFIf_JzHxFXlKs', True),
            ('AVNS_UahLjsENr4QexJ1', True),
            ('foo', False),
            ('AVNS_', False),  # Incomplete token
            ('AVNS12345678', False),  # Missing underscore
            ('AVNS_UahLjs', False),  # Too short
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = AivenTokenDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)
