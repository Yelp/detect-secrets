from typing import Any

from detect_secrets.core.potential_secret import PotentialSecret


def potential_secret_factory(
    type: str = 'type',
    filename: str = 'filename',
    secret: str = 'secret',
    line_number: int = 1,
    **kwargs: Any,
) -> PotentialSecret:
    """This is only marginally better than creating PotentialSecret objects directly,
    because of the default values.
    """
    return PotentialSecret(
        type=type,
        filename=filename,
        secret=secret,
        line_number=line_number,
        **kwargs
    )
