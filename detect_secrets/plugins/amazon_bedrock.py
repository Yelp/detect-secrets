"""
This plugin searches for Amazon Bedrock API keys
"""
import re

from detect_secrets.plugins.base import RegexBasedDetector

class AmazonBedrockApiKeyDetector(RegexBasedDetector):
    """Scans for Amazon Bedrock API keys."""
    secret_type = 'Amazon Bedrock API key'

    denylist = [
        # refs https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys.html
        # Long-lived keys begin with ABSK
        re.compile(r'(?<![A-Za-z0-9+/=])ABSK[A-Za-z0-9+/]{109,269}={0,2}(?![A-Za-z0-9+/=])'),
        # Short-lived keys begin with bedrock-api-key-
        re.compile(r'bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t')
    ]
