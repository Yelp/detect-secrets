# We don't scan files with these extensions.
# NOTE: We might be able to do this better with
#       `subprocess.check_output(['file', filename])`
#       and look for "ASCII text", but that might be more expensive.
#
#       Definitely something to look into, if this list gets unruly long.
IGNORED_FILE_EXTENSIONS = {
    '7z',
    'bmp',
    'bz2',
    'dmg',
    'exe',
    'gif',
    'gz',
    'ico',
    'jar',
    'jpg',
    'jpeg',
    'png',
    'rar',
    'realm',
    's7z',
    'tar',
    'tif',
    'tiff',
    'webp',
    'zip',
}
