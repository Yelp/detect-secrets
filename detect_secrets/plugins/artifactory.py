from __future__ import absolute_import

import re

from .base import RegexBasedDetector


class ArtifactoryDetector(RegexBasedDetector):

    secret_type = 'Artifactory Credentials'

    blacklist = [
        # artifactory tokens begin with AKC
        re.compile(r'(\s|=|:|"|^)AKC\w{10,}'),    # api token
        # artifactory encrypted passwords begin with AP6
        re.compile(r'(\s|=|:|"|^)AP6\w{10,}'),    # password
    ]
