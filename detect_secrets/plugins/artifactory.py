import re

from .base import RegexBasedDetector


class ArtifactoryDetector(RegexBasedDetector):
    """Scans for Artifactory credentials."""
    secret_type = 'Artifactory Credentials'

    denylist = [
        # Artifactory tokens begin with AKC
        # API token:
        re.compile(r'(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}(?:\s|"|$)'),
        # Artifactory encrypted passwords begin with AP[A-Z]
        # Password:
        re.compile(r'(?<!AAAA[_\-\w]{7})(?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}(?:\s|"|$)'),
    ]
