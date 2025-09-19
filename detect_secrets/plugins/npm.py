"""
This plugin searches for NPM tokens
"""
import re

from detect_secrets.plugins.base import RegexBasedDetector


class NpmDetector(RegexBasedDetector):
    """Scans for NPM tokens."""
    secret_type = 'NPM tokens'

    denylist = [
        # npmrc authToken - UUID format or npm_ prefixed tokens
        # ref. https://stackoverflow.com/questions/53099434/using-auth-tokens-in-npmrc
        re.compile(r'\/\/.+\/:_authToken=\s*((npm_.+)|([A-Fa-f0-9-]{36})).*'),
        
        # npmrc _auth - base64 encoded credentials
        # ref. https://docs.npmjs.com/cli/v9/configuring-npm/npmrc#auth
        re.compile(r'\/\/.+\/:_auth=\s*[A-Za-z0-9+/=]+.*'),
        
        # npmrc _authToken - arbitrary token formats (excludes UUID and npm_ patterns)
        # covers custom tokens that don't match UUID or npm_ prefix patterns
        re.compile(r'\/\/.+\/:_authToken=\s*(?!npm_)(?![A-Fa-f0-9-]{36})[A-Za-z0-9_-]+.*'),
    ]
