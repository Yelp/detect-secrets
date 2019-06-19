from __future__ import absolute_import

import re

from .base import RegexBasedDetector


class ArtifactoryDetector(RegexBasedDetector):

    secret_type = 'Artifactory Credentials'

    denylist = [
        # artifactory tokens begin with AKC
        re.compile(r'(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}'),    # api token
        # artifactory encrypted passwords begin with AP[A-Z]
        re.compile(r'(?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}'),    # password
    ]
