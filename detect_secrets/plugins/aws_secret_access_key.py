from detect_secrets.plugins.base import RegexBasedDetector


class AWSSSecretAccessKeyDetector(RegexBasedDetector):
    """Scans for AWS secret-access-key."""

    secret_type = 'AWS Secret Access Key'
    disable_flag_text = 'no-aws-secret-access-key-scan'

    prefix = r'*'
    aws_secret_keywords = r'.*(?:aws|secret|access|key).*'
    secret_pattern = r'(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])'

    denylist = [
        RegexBasedDetector.assign_regex_generator(
            prefix_regex=prefix,
            secret_keyword_regex=aws_secret_keywords,
            secret_regex=secret_pattern,
        ),
    ]
