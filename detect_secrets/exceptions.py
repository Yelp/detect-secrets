class UnableToReadBaselineError(ValueError):
    """Think of this as a 404, if getting a baseline had a HTTPError code."""
    pass


class InvalidBaselineError(ValueError):
    """Think of this as a 400, if getting a baseline had a HTTPError code."""
    pass


class InvalidFile(ValueError):
    """Think of this as a 400, if FileNotFoundError was a 404 HTTPError code."""
    pass


class SecretNotFoundOnSpecifiedLineError(Exception):
    def __init__(self, line):
        super(SecretNotFoundOnSpecifiedLineError, self).__init__(
            'ERROR: Secret not found on line {}!\n'.format(line)
            + 'Try recreating your baseline to fix this issue.',
        )
