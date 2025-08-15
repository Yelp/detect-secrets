import pytest

from detect_secrets.plugins.amazon_bedrock import AmazonBedrockApiKeyDetector


class TestAmazonBedrockDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('ABSKQmVkcm9ja0FQSUtleS1EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXM=', True),
            ('ABSKQmVkcm9ja0FQSUtleS1', False),
            ('bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29tEXAMPLE', True),
            ('bedrock-api-key', False),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = AmazonBedrockApiKeyDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)

        assert len(output) == int(should_flag)
