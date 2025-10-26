import re
from typing import Iterable

from .base import RegexBasedDetector


class PiiDetector(RegexBasedDetector):
    """Simple regex-based PII detector for logs.

    This is intentionally conservative and intended as an example. Tune regexes
    for your data (reduce false positives / increase coverage) before using in CI.
    """
    secret_type = 'PII'

    # Common PII patterns. Keep the patterns non-greedy and avoid unnecessary capture groups.
    EMAIL = r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    PHONE = r'(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}'
    IPV4 = r'\b(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:\.(?:25[0-5]|2[0-4]\d|1?\d{1,2})){3}\b'
    CREDIT_CARD = r'\b(?:\d[ -]*?){13,19}\b'
    SSN = r'\b\d{3}-\d{2}-\d{4}\b'
    # Very naive password capture (common key name patterns)
    PASSWORD = r'(?i)(?:password|pwd|pass)\s*[=:]\s*[^\s,]+'

    denylist: Iterable[re.Pattern] = (
        re.compile(EMAIL),
        re.compile(PHONE),
        re.compile(IPV4),
        re.compile(CREDIT_CARD),
        re.compile(SSN),
        re.compile(PASSWORD),
    )
