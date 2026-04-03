"""
This plugin searches for HashiCorp Vault tokens
"""
import re

from detect_secrets.plugins.base import RegexBasedDetector


class HashiCorpVaultTokenDetector(RegexBasedDetector):
    """Scans for HashiCorp Vault tokens."""
    secret_type = 'HashiCorp Vault Token'

    denylist = [
        # ref. https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/
        # \b has been added to avoid many false positives when using Vault <=1.9 tokens
        re.compile(r'(?:hv|\b)[brs]\.[A-Za-z0-9_-]{24,}'),
    ]
