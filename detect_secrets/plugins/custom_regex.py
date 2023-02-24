import re
from ..settings import get_settings
from .base import RegexBasedDetector



class CustomRegex(RegexBasedDetector):
    """Scans for Basic Auth formatted URIs."""
    secret_type = 'Custom_Regex'
    patterns = get_settings().custom_regex
    def denylist(self) :
        deny = {}
        for pattern in self.patterns:
            deny[self.patterns[pattern]] = re.compile(self.patterns[pattern])
        return deny

    def analyze_string(self, string: str):
        index = 0
        deny = self.denylist()
        for regex in deny:
            self.secret_type = self.patterns.inverse[regex]
            for match in deny[regex].findall(string):
                if isinstance(match, tuple):
                    for submatch in filter(bool, match):
                        # It might make sense to paste break after yielding
                        yield submatch
                else:
                    yield match
    # denylist = [
    #     re.compile(
    #         r'([a-zA-Z0-9+/]{40})',
    #     ),
    # ]
