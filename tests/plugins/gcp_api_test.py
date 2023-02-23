import pytest

from detect_secrets.plugins.gcp_key import GcpkeyDetector
from detect_secrets.plugins.discord import DiscordBotTokenDetector


class TestGcpKeyDetector:
    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            # reference = https://cloud.google.com/docs/authentication/api-keys?hl=pt-br
            ("AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe", True),

            # random string for api key testing
            ("AIZA SNDSAUDHS ASASA DSIAOSIA", False),

            # changed oauth client-id 
            ("625842392116-saklt1i2jf2bjbtf6gneknq3lrgg96ca.apps.googleusercontent.com", True)
        ],
    )
    def test_analyze(self, payload, should_flag):
        print(payload,should_flag)
        assert payload != None
        logic = GcpkeyDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        print(len(output))
        assert len(output) == int(should_flag)
