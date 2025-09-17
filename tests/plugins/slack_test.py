import pytest

from detect_secrets.plugins.slack import SlackDetector


class TestSlackDetector:

    @pytest.mark.parametrize(
        'line',
        [
            (
                'xoxp-523423-234243-234233-e039d02840a0b9379c'
            ),
            (
                'xoxo-523423-234243-234233-e039d02840a0b9379c'
            ),
            (
                'xoxs-523423-234243-234233-e039d02840a0b9379c'
            ),
            (
                'xoxa-511111111-31111111111-3111111111111-e039d02840a0b9379c'
            ),
            (
                'xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c'
            ),
            (
                'xoxr-523423-234243-234233-e039d02840a0b9379c'
            ),
            (
                'xoxc-1234567890-1234567890-abcdef1234567890abcdef1234567890'
            ),
            (
                'xoxc-123456789-987654321-1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p'
            ),
            (
                'xoxc-111111111-222222222-aaaabbbbccccddddeeeeffffgggghhh'
            ),
            (
                'xoxb-34532454-e039d02840a0b9379c'
            ),
            (
                'https://hooks.slack.com/services/Txxxxxxxx/Bxxxxxxxx/xxxxxxxxxxxxxxxxxxxxxxxx'
            ),
        ],
    )
    def test_analyze(self, line):
        logic = SlackDetector()

        output = logic.analyze_line(filename='mock_filename', line=line)
        assert len(output) == 1
