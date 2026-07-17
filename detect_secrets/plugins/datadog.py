"""
This plugin searches for Datadog API keys and Application keys.

Datadog API keys are 32-character hexadecimal strings.
Datadog Application keys are 40-character hexadecimal strings.
"""
import re

import requests

from ..constants import VerifiedResult
from .base import RegexBasedDetector


class DatadogDetector(RegexBasedDetector):
    """Scans for Datadog API and Application keys."""
    secret_type = 'Datadog Access Key'

    denylist = [
        # Datadog API key (32 hex characters) with contextual prefix
        re.compile(
            r'(?:dd|datadog)[_-]?(?:api)[_-]?key\s*[:=]\s*["\']?([a-f0-9]{32})["\']?',
            flags=re.IGNORECASE,
        ),
        # Datadog Application key (40 hex characters) with contextual prefix
        re.compile(
            r'(?:dd|datadog)[_-]?(?:app|application)[_-]?key\s*[:=]\s*["\']?([a-f0-9]{40})["\']?',
            flags=re.IGNORECASE,
        ),
    ]

    def verify(self, secret: str) -> VerifiedResult:  # pragma: no cover
        response = requests.get(
            'https://api.datadoghq.com/api/v1/validate',
            headers={
                'DD-API-KEY': secret,
            },
        )

        if response.status_code == 200:
            return VerifiedResult.VERIFIED_TRUE

        return VerifiedResult.VERIFIED_FALSE
