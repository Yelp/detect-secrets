import re

from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.plugins.base import RegexBasedDetector


class AWSSSecretAccessKeyDetector(RegexBasedDetector):
    """Scans for AWS secret-access-key."""

    secret_type = 'AWS Secret Access Key'
    disable_flag_text = 'no-aws-secret-access-key-scan'

    def analyze_string_content(self, string, line_num, filename):
        output = {}

        if 'aws' not in string and 'secret' not in string and 'access' not in string:
            return output

        match = re.search(r'(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])', string)
        if match:
            secret = PotentialSecret(
                self.secret_type,
                filename,
                string,
                line_num,
            )
            output[secret] = secret

        return output
