import re

from detect_secrets.plugins.base import RegexBasedDetector


class DessertDetector(RegexBasedDetector):
    """Scans for tasty desserts."""
    secret_type = 'Tasty Dessert'
    denylist = (
        re.compile(
            r"(reese's peanut butter chocolate cake cheesecake|sweet potato casserole)",
            re.IGNORECASE,
        ),
    )
