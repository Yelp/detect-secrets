from __future__ import annotations

from typing import Any
from typing import Set
from typing import Union

import requests

from ..constants import VerifiedResult
from ..core.potential_secret import PotentialSecret
from ..util.code_snippet import CodeSnippet
from .base import RegexBasedDetector
from .high_entropy_strings import Base64HighEntropyString


class IbmCloudIamDetector(RegexBasedDetector):
    """Scans for IBM Cloud IAM Key."""

    secret_type = 'IBM Cloud IAM Key'
    # opt means optional
    opt_ibm_cloud_iam = r'(?:ibm(?:_|-|)cloud(?:_|-|)iam|cloud(?:_|-|)iam|' + \
        r'ibm(?:_|-|)cloud|ibm(?:_|-|)iam|ibm|iam|cloud|)'
    opt_dash_underscore = r'(?:_|-|)'
    opt_api = r'(?:api|platform|)'
    key_or_pass = r'(?:key|pwd|password|pass|token)'
    secret = r'([a-zA-Z0-9_\-]{44}(?![a-zA-Z0-9_\-]))'
    denylist = [
        RegexBasedDetector.build_assignment_regex(
            prefix_regex=opt_ibm_cloud_iam + opt_dash_underscore + opt_api,
            secret_keyword_regex=key_or_pass,
            secret_regex=secret,
        ),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.entropy_plugin = Base64HighEntropyString()

    def verify(self, secret: str) -> VerifiedResult:
        response = verify_cloud_iam_api_key(secret)

        return VerifiedResult.VERIFIED_TRUE if response.status_code == 200 \
            else VerifiedResult.VERIFIED_FALSE

    def analyze_line(
        self,
        filename: str,
        line: str,
        line_number: int = 0,
        context: CodeSnippet | None = None,
        raw_context: CodeSnippet | None = None,
        **kwargs: Any,
    ) -> Set[PotentialSecret]:
        potentials = super().analyze_line(
            filename, line, line_number, context, raw_context, **kwargs,
        )
        secrets = set()
        for p in potentials:
            if self.entropy_plugin.analyze_line(
                    filename, f'"{p.secret_value}"', line_number, context, raw_context, **kwargs,
            ):
                secrets.add(p)
        return secrets


def verify_cloud_iam_api_key(apikey: Union[str, bytes]) -> requests.Response:  # pragma: no cover
    if isinstance(apikey, bytes):
        apikey = apikey.decode('UTF-8')

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
    }
    response = requests.post(
        'https://iam.cloud.ibm.com/identity/token',
        headers=headers,
        data={
            'grant_type': 'urn:ibm:params:oauth:grant-type:apikey',
            'apikey': apikey,
        },
    )
    return response
