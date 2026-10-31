"""
This plugin searches for Nuntiq API keys and rotation secrets.
"""
import re
import zlib
from typing import Generator

import requests

from ..constants import VerifiedResult
from .base import RegexBasedDetector


BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

# The customer API answers the key check for the environment named in the key.
HOSTS = {
    'live': 'api.apreceiving.com',
    'test': 'test-api.apreceiving.com',
    'dev': 'dev-api.apreceiving.com',
}


def checksum(random_part: str) -> str:
    """CRC32 (IEEE) of the random part as 6 base62 digits, most significant first."""
    value = zlib.crc32(random_part.encode('ascii'))
    digits = []
    for _ in range(6):
        value, remainder = divmod(value, 62)
        digits.append(BASE62[remainder])
    return ''.join(reversed(digits))


class NuntiqDetector(RegexBasedDetector):
    """Scans for Nuntiq API keys and rotation secrets."""
    secret_type = 'Nuntiq API Key'

    denylist = (
        # nuntiq_<kind>_<environment>_<8 hex key id>_<43 base64url random><6 base62 checksum>
        # kind: ck (customer API key), pk (partner API key), rs (rotation secret)
        # environment: live, test, dev
        # The lookarounds keep a match from starting or ending inside a longer token.
        re.compile(
            r'(?<![A-Za-z0-9_-])'
            r'(nuntiq_(?:ck|pk|rs)_(?:live|test|dev)_[0-9a-f]{8}_[A-Za-z0-9_-]{43}[0-9A-Za-z]{6})'
            r'(?![A-Za-z0-9_-])',
        ),
    )

    def analyze_string(self, string: str) -> Generator[str, None, None]:
        # The last 6 characters are a checksum of the 43 before them, so a look-alike with a
        # wrong checksum is not reported.
        for match in super().analyze_string(string):
            if checksum(match[-49:-6]) == match[-6:]:
                yield match

    def verify(self, secret: str) -> VerifiedResult:
        # POST /api/v1/key-check answers 200 with {"valid": bool, "kind": ..., "environment": ...}
        # for every credential and returns nothing about the account.
        environment = secret.split('_')[2]
        response = requests.post(
            'https://{}/api/v1/key-check'.format(HOSTS[environment]),
            headers={'X-API-Key': secret},
            timeout=10,
        )
        if response.status_code != 200:
            return VerifiedResult.UNVERIFIED

        try:
            valid = response.json().get('valid')
        except (ValueError, AttributeError):
            return VerifiedResult.UNVERIFIED

        if valid is True:
            return VerifiedResult.VERIFIED_TRUE
        if valid is False:
            return VerifiedResult.VERIFIED_FALSE
        return VerifiedResult.UNVERIFIED
