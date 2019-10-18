from enum import Enum


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


class VerifiedResult(Enum):
    UNVERIFIED = 1
    VERIFIED_FALSE = 2
    VERIFIED_TRUE = 3
