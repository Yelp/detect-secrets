import re

from detect_secrets.plugins.base import classproperty
from detect_secrets.plugins.base import RegexBasedDetector


class HippoDetector(RegexBasedDetector):
    """Scans for hippos."""
    secret_type = 'Hippo'

    @classproperty
    def disable_flag_text(cls):
        return 'no-hippo-scan'

    denylist = (
        re.compile(
            r'(hippo)',
            re.IGNORECASE,
        ),
    )
