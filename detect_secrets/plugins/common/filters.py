"""
Heuristic, false positive filters that are shared across all plugin types.
This abstraction allows for development of later ML work, or further
heuristical determinations (e.g. word filter, entropy comparator).
"""
import string


def is_false_positive(secret):
    for func in [
        is_sequential_string,
    ]:
        if func(secret):
            return True

    return False


def is_sequential_string(secret):
    """
    Returns true if string is sequential.
    """
    sequences = (
        (
            string.ascii_uppercase +
            string.ascii_uppercase +
            string.digits +
            string.ascii_uppercase +
            string.ascii_uppercase +
            '+/'
        ),

        # Capturing any number sequences
        '0123456789' * 2,

        string.hexdigits.upper() + string.hexdigits.upper(),
        string.ascii_uppercase + '=/',
    )

    uppercase = secret.upper()
    for sequential_string in sequences:
        if uppercase in sequential_string:
            return True

    return False
