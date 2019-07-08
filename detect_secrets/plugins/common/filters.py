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
        # base64 letters first
        (
            string.ascii_uppercase +
            string.ascii_uppercase +
            string.digits +
            '+/'
        ),

        # base64 numbers first
        (
            string.digits +
            string.ascii_uppercase +
            string.ascii_uppercase +
            '+/'
        ),

        # We don't have a specific sequence for alphabetical
        # sequences, since those will happen to be caught by the
        # base64 checks.

        # alphanumeric sequences
        (string.digits + string.ascii_uppercase) * 2,

        # Capturing any number sequences
        string.digits * 2,

        string.hexdigits.upper() + string.hexdigits.upper(),
        string.ascii_uppercase + '=/',
    )

    uppercase = secret.upper()
    for sequential_string in sequences:
        if uppercase in sequential_string:
            return True

    return False
