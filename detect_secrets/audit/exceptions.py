class SecretNotFoundOnSpecifiedLineError(Exception):
    def __init__(self, line):
        super(SecretNotFoundOnSpecifiedLineError, self).__init__(
            'ERROR: Secret not found on line {}!\n'.format(line)
            + 'Try recreating your baseline to fix this issue.',
        )


class RedundantComparisonError(Exception):
    pass
