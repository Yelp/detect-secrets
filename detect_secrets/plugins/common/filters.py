"""
False positive heuristic filters that are shared across all plugin types.
This abstraction allows for development of later ML work, or further
heuristical determinations (e.g. word filter, entropy comparator).
"""
import string

from detect_secrets.util import is_python_2


def is_false_positive(secret, automaton):
    """
    :type secret: str

    :type automaton: ahocorasick.Automaton|None
    :param automaton: optional automaton for ignoring certain words.

    :rtype: bool
    Returns True if any false positive heuristic function returns True.
    """
    return any(
        func(secret, automaton)
        for func in
        (
            _is_found_with_aho_corasick,
            _is_sequential_string,
        )
    )


def _is_found_with_aho_corasick(secret, automaton):
    """
    :type secret: str

    :type automaton: ahocorasick.Automaton|None
    :param automaton: optional automaton for ignoring certain words.

    :rtype: bool
    Returns True if secret contains a word in the automaton.
    """
    if not automaton:
        return False

    if is_python_2():  # pragma: no cover
        # Due to pyahocorasick
        secret = secret.encode('utf-8')

    try:
        # .lower() to make everything case-insensitive
        next(automaton.iter(string=secret.lower()))
        return True
    except StopIteration:
        return False


def _is_sequential_string(secret, *args):
    """
    :type secret: str

    :rtype: bool
    Returns True if string is sequential.
    """
    sequences = (
        # Base64 letters first
        (
            string.ascii_uppercase +
            string.ascii_uppercase +
            string.digits +
            '+/'
        ),

        # Base64 numbers first
        (
            string.digits +
            string.ascii_uppercase +
            string.ascii_uppercase +
            '+/'
        ),

        # We don't have a specific sequence for alphabetical
        # sequences, since those will happen to be caught by the
        # base64 checks.

        # Alphanumeric sequences
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
