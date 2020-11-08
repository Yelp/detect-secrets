class UnableToReadBaselineError(ValueError):
    """Think of this as a 404, if getting a baseline had a HTTPError code."""
    pass


class InvalidBaselineError(ValueError):
    """Think of this as a 400, if getting a baseline had a HTTPError code."""
    pass
