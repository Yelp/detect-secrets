import re

from .base import RegexBasedDetector


class ArtifactoryDetector(RegexBasedDetector):
    """Scans for Artifactory credentials."""
    secret_type = 'Artifactory Credentials'

    denylist = [
        # Artifactory tokens begin with AKC
        # API token:
        re.compile(r'(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,200}(?:\s|"|$)'),
        # Artifactory encrypted passwords begin with AP[A-Z]
        # Keyword with Password:
        re.compile(r'(?<!AAAA[_\-\w]{7})(?i:artif|jfrog|buildkit)(?:.{0,100}\n?){0,2}(?:\s|=|:|"|^)(AP[\dABCDEF][a-zA-Z0-9]{8,200})(?:\s|"|$)'),
    ]
