"""
This plugin searches for GitLab tokens
"""
import re

from detect_secrets.plugins.base import RegexBasedDetector


class GitLabTokenDetector(RegexBasedDetector):
    """Scans for GitLab tokens."""

    secret_type = 'GitLab Token'

    denylist = [
        # ref. https://docs.gitlab.com/ee/security/token_overview.html#gitlab-tokens
        # `gl..-` prefix and a token of length >20
        #       chars are alphanumeric, underscore, dash

        # Default is a `Devise.friendly_token`-generated token, it has a default length
        # of 20 chars. But it may be longer depending on the type of token, and probably
        # even GL-settings in the future.
        # We assume that 20 chars is the minimum length and 50 chars is the maximum length.
        re.compile(
            r'(glpat|gloas|gldt|glrt|glcbt|glptt|glft|glimt|glagent|glsoat)-'
            r'[A-Za-z0-9_\-]{20,50}(?!\w)',
        ),
    ]
