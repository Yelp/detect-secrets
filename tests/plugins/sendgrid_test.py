import pytest

from detect_secrets.plugins.sendgrid import SendGridDetector


class TestSendGridDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('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', True),
            ('SG.ngeVfQFYQlKU0ufo8x5d1A..TwL2iGABf9DHoTf-09kqeF8tAmbihYzrnopKc-1s5cr', False),
            ('AG.ngeVfQFYQlKU0ufo8x5d1A.TwL2iGABf9DHoTf-09kqeF8tAmbihYzrnopKc-1s5cr', False),
            ('foo', False),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = SendGridDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)
