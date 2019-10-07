import pytest

from detect_secrets.plugins.box import BoxDetector


class TestBoxDetector(object):

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('"clientSecret": "12345678abcdefgh12345678ABCDEFGH"', True),
            ('client_secret = 12345678abcdefgh12345678ABCDEFGH', True),
            ('CLIENT-SECRET=12345678abcdefgh12345678ABCDEFGH', True),
            ('"clientsecret":="12345678abcdefgh12345678ABCDEFGH"', True),
            ('"clientSecret": "12345678abcdefgh12345678ABCDEFG2many"', True),
            ('"clientSecret": "12345678abcdnotenough"', False),
        ],
    )
    def test_analyze_string(self, payload, should_flag):
        logic = BoxDetector()

        output = logic.analyze_string(payload, 1, 'mock_filename')
        assert len(output) == int(should_flag)
