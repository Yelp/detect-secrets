"""
False positive heuristic filters that are shared across all plugin types.
This abstraction allows for development of later ML work, or further
heuristical determinations (e.g. word filter, entropy comparator).
"""
import re
import string


def is_found_with_aho_corasick(secret, automaton):
    """
    :type secret: str

    :type automaton: ahocorasick.Automaton|None
    :param automaton: optional automaton for ignoring certain words.

    :rtype: bool
    Returns True if secret contains a word in the automaton.
    """
    if not automaton:
        return False

    try:
        # .lower() to make everything case-insensitive
        next(automaton.iter(string=secret.lower()))
        return True
    except StopIteration:
        return False


def get_aho_corasick_helper(automaton):
    """
    Returns a function which determines if a word matches the
    input automaton.

    :type automaton: ahocorasick.Automaton
    """
    def fn(secret):
        return is_found_with_aho_corasick(secret, automaton)

    return fn


def is_sequential_string(secret, *args):
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


_UUID_REGEX = re.compile(
    r'[a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12}',
    re.IGNORECASE,
)


def is_potential_uuid(secret, *args):
    """
    Determines if a potential secret contains any UUIDs.

    :type secret: str

    :rtype: bool
    Returns True if the string has a UUID, false otherwise.
    """

    # Using a regex to find strings that look like false-positives
    # will find us more false-positives than if we just tried validate
    # the input string as a UUID (for example, if the string has a prefix
    # or suffix).
    return bool(_UUID_REGEX.search(secret))


# NOTE: this doesn't handle multiple key-values on a line properly.
# NOTE: words that end in "id" will be treated as ids
_ID_DETECTOR_REGEX = re.compile(r'id[^a-z0-9]', re.IGNORECASE)


def is_likely_id_string(secret, line):
    """
    :type secret: str

    :type line: str
    :param line: Line context for the plaintext secret

    :rtype: bool
    Returns true if the secret could be an id, false otherwise.
    """
    if secret not in line:
        return False

    secret_index = line.index(secret)
    return bool(_ID_DETECTOR_REGEX.search(line, pos=0, endpos=secret_index))


DEFAULT_FALSE_POSITIVE_WITH_LINE_CONTEXT_HEURISTICS = [
    is_likely_id_string,
]


def is_false_positive_with_line_context(
    secret,
    line,
    functions=DEFAULT_FALSE_POSITIVE_WITH_LINE_CONTEXT_HEURISTICS,
):
    """
    :type secret: str

    :type line: str
    :param line: plaintext line on which secret was found

    :type functions: Iterable[Callable]
    :param functions: list of heuristics to use

    :rtype: bool
    Returns True if any false-positive heuristic which considers the whole file line
    returns true.
    """
    return any(
        func(secret, line)
        for func in functions
    )
