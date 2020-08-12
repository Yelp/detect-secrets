import pytest

from detect_secrets.plugins.aws_secret_access_key import AWSSSecretAccessKeyDetector


class TestAWSSecretAccessKeyDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('my_id: AKIAIOSFODNN7EXAMPLE', False),
            ('aws_secret_access_key: AKIAIOSFODNN7EXAMPLE', False),
            ('aws_secret_access_key: not_secret_key', False),
            ('some_other_40_char_base64_str: pARhvm1GmHyvLydUtFNCCMIIu4VEyaZNo9MbR3IJ', False),
            ('some_secret_key=DcCc9H6oCkGUSp3Rhmsx8NIfVG8kO2T/3jORxuZY', True),
            ('secret  =   wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', True),
            ('someGarbageInfront aws_secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', True),
            ('aws_thingy:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', True),
        ],
    )
    def test_analyze_line(self, payload, should_flag):
        logic = AWSSSecretAccessKeyDetector()

        output = logic.analyze_line(payload, 1, 'mock_filename')
        assert len(output) == int(should_flag)
