import re

import requests

from .base import RegexBasedDetector
from detect_secrets.core.constants import VerifiedResult


class ArtifactoryDetector(RegexBasedDetector):
    """Scans for Artifactory credentials."""
    secret_type = 'Artifactory Credentials'

    denylist = [
        # Artifactory tokens begin with AKC
        re.compile(r'(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}'),  # API token
        # Artifactory encrypted passwords begin with AP[A-Z]
        re.compile(r'(?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}'),  # Password
    ]

    artifactory_url = 'na.artifactory.swg-devops.com/artifactory'

    def verify(self, token, **kwargs):
        try:
            if type(token) == bytes:
                token = token.decode('UTF-8')
            headers = {'X-JFrog-Art-API': token}
            response = requests.get(
                'https://%s/api/system/ping' % self.artifactory_url,
                headers=headers,
            )
            if response.status_code == 200:
                return VerifiedResult.VERIFIED_TRUE
            elif response.status_code == 401:
                return VerifiedResult.VERIFIED_FALSE
            else:
                return VerifiedResult.UNVERIFIED
        except Exception:
            return VerifiedResult.UNVERIFIED
