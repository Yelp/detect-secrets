import pytest

from detect_secrets.plugins.okta import OktaDetector


class TestOktaDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            # pragma: allowlist nextline secret
            ('00ZDreYRgPTWY4MpAf5ED9TVXjfS9XKxT6Fy3fC7uA', True),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = OktaDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)

        assert len(output) == int(should_flag)
