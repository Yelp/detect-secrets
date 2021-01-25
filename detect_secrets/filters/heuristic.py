import os
import re
import string
from functools import lru_cache
from typing import Pattern


def is_sequential_string(secret: str) -> bool:
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


def is_potential_uuid(secret: str) -> bool:
    return bool(_get_uuid_regex().search(secret))


@lru_cache(maxsize=1)
def _get_uuid_regex() -> Pattern:
    return re.compile(
        r'[a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12}',
        re.IGNORECASE,
    )


def is_likely_id_string(secret: str, line: str) -> bool:
    try:
        index = line.index(secret)
    except ValueError:
        return False

    return bool(_get_id_detector_regex().search(line, pos=0, endpos=index))


@lru_cache(maxsize=1)
def _get_id_detector_regex() -> Pattern:
    return re.compile(r'id[^a-z0-9]', re.IGNORECASE)


def is_non_text_file(filename: str) -> bool:
    _, ext = os.path.splitext(filename)
    return ext in IGNORED_FILE_EXTENSIONS


# We don't scan files with these extensions.
# Note: We might be able to do this better with
#       `subprocess.check_output(['file', filename])`
#       and look for "ASCII text", but that might be more expensive.
#
#       Definitely something to look into, if this list gets unruly long.
IGNORED_FILE_EXTENSIONS = set(
    (
        '.7z',
        '.bmp',
        '.bz2',
        '.dmg',
        '.eot',
        '.exe',
        '.gif',
        '.gz',
        '.ico',
        '.jar',
        '.jpg',
        '.jpeg',
        '.mo',
        '.png',
        '.rar',
        '.realm',
        '.s7z',
        '.svg',
        '.tar',
        '.tif',
        '.tiff',
        '.ttf',
        '.webp',
        '.woff',
        '.xls',
        '.xlsx',
        '.zip',
    ),
)


def is_templated_secret(secret: str) -> bool:
    """
    Filters secrets that are shaped like: {secret}, <secret>, or ${secret}.
    """
    try:
        if (
            (secret[0] == '{' and secret[-1] == '}')
            or (secret[0] == '<' and secret[-1] == '>')
            or (secret[0] == '$' and secret[1] == '{' and secret[-1] == '}')
        ):
            return True
    except IndexError:
        # Any one character secret (that causes this to raise an IndexError) is highly
        # likely to be a false positive (or if a true positive, INCREDIBLY weak password).
        return True

    return False


def is_prefixed_with_dollar_sign(secret: str) -> bool:
    # NOTE: This is broken out into its own function since it has more chance of increasing
    # false negatives than `is_templated_secret` (e.g. secrets that actually start with a $).
    # This is best used with files that actually use this as a means of referencing variables.
    # TODO: More intelligent filetype handling?
    return secret[0] == '$'


def is_indirect_reference(secret: str) -> bool:
    """
    Filters secrets that take the form of:

        secret = get_secret_key()

    or

        secret = request.headers['apikey']
    """
    output = False
    for start, end in (
        list('()'),
        list('[]'),
    ):
        try:
            output = secret.index(start) < secret.index(end)
            if output:
                return output
        except ValueError:
            continue

    return output
