from enum import Enum
import re

from detect_secrets.core import private_corporation as corp


# We don't scan files with these extensions.
# Note: We might be able to do this better with
#       `subprocess.check_output(['file', filename])`
#       and look for "ASCII text", but that might be more expensive.
#
#       Definitely something to look into, if this list gets unruly long.
IGNORED_FILE_EXTENSIONS = set(
    (
        '.7z',
        '.bin',
        '.bmp',
        '.bz2',
        '.class',
        '.css',
        '.dmg',
        '.doc',
        '.eot',
        '.exe',
        '.gif',
        '.gz',
        '.ico',
        '.iml',
        '.ipr',
        '.iws',
        '.jar',
        '.jpg',
        '.jpeg',
        '.lock',
        '.map',
        '.mo',
        '.pdf',
        '.png',
		'.prefs',
        '.psd',
        '.rar',
        '.realm',
        '.s7z',
		'.sum',
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

IGNORED_FILE_NAMES = set(
    (
        'package.json',
        'package-lock.json',
        'mock.properties',
		'checkstyle-java-google-style.xml',
        '.settings',
        'netbeans.conf',
        '.secret.baseline',
    ),
)
IGNORED_FILE_NAMES.update(corp.IGNORED_FILE_NAMES)

IGNORED_FILE_NAMES_REGEX = set(
	(	
		re.compile(file_name)
		for file_name in [
			r'((m|M)essages|storetext)(_[a-z]{2}(_[A-Z]{2})?)?\.properties',
			r'.*swagger.*'
			r'.*ckeditor.*'
		]
	),
)
IGNORED_FILE_NAMES_REGEX.update(corp.IGNORED_FILE_NAMES_REGEX)

IGNORED_FILE_PATHS = set(
    (
        '.git',
        '.svn',
        '.idea',
        '.vscode',
        'node_modules',
        'site-packages',
        'target',
        'translations',
        'traducciones',
        'i18n',
        'l10n',
        'espanol',
        'english',
        'portugues',
        'francais',
        'deutsch',
        'italiano',
        'polski',
        'locale',
        '.settings',
        'netbeans.conf',
        '.netbeans',
    ),
)
IGNORED_FILE_PATHS.update(corp.IGNORED_FILE_PATHS)

COMMON_PASSWORDS = set(
    (
        'password',
        'secret',
        'admin',
        'prueba',
    )
)
COMMON_PASSWORDS.update(corp.COMMON_PASSWORDS)

class VerifiedResult(Enum):
    UNVERIFIED = 1
    VERIFIED_FALSE = 2
    VERIFIED_TRUE = 3
