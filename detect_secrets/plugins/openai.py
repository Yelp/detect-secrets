"""
This plugin searches for OpenAI tokens
"""
import re

from detect_secrets.plugins.base import RegexBasedDetector


class OpenAIDetector(RegexBasedDetector):
    """Scans for OpenAI tokens."""
    secret_type = 'OpenAI Token'

    denylist = [
        # refs https://community.openai.com/t/what-are-the-valid-characters-for-the-apikey/288643
        # User api keys (legacy): 'sk-[20 alnum]T3BlbkFJ[20 alnum]'
        # Project-based api keys (legacy): 'sk-[project-name]-[20 alnum]T3BlbkFJ[20 alnum]'
        re.compile(r'sk-[A-Za-z0-9-_]*[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}'),
        
        # New API key formats starting with sk-proj-, sk-svcacct- or others without T3BlbkFJ.
        re.compile(r'sk-[a-zA-Z0-9-]{1,30}-[a-zA-Z0-9_-]{40,}'),
    ]
