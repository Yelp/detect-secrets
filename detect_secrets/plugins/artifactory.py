import re

import requests

from .base import RegexBasedDetector
from detect_secrets.core.constants import VerifiedResult


class ArtifactoryDetector(RegexBasedDetector):
    """Scans for Artifactory credentials."""
    secret_type = 'Artifactory Credentials'

    denylist = [
        # artifactory tokens begin with AKC
        re.compile(r'(?:(?<==|:|")|(?<=\s)|(?<=^))AKC[a-zA-Z0-9]{10,}'),    # api token
        # artifactory encrypted passwords begin with AP[A-Z]
        re.compile(r'(?:(?<==|:|")|(?<=\s)|(?<=^))AP[\dABCDEF][a-zA-Z0-9]{8,}'),    # password
    ]

    artifactory_url = 'na.artifactory.swg-devops.com/artifactory'

    def verify(self, token, *args, **kwargs):
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
            elif response.status_code == 401 or response.status_code == 403:
                return VerifiedResult.VERIFIED_FALSE
            else:
                return VerifiedResult.UNVERIFIED
        except requests.exceptions.RequestException:
            return VerifiedResult.UNVERIFIED
