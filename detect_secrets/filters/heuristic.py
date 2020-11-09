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
