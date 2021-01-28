import re
from typing import Any
from typing import Dict
from typing import Generator
from typing import Optional
from typing import Pattern
from typing import Set

from ..core.potential_secret import PotentialSecret
from ..util.filetype import determine_file_type
from ..util.filetype import FileType
from .base import BasePlugin

# Note: All values here should be lowercase
DENYLIST = (
    'apikey',
    'api_key',
    'appkey',
    'app_key',
    'authkey',
    'auth_key',
    'servicekey',
    'service_key',
    'applicationkey',
    'application_key',
    'accountkey',
    'account_key',
    'dbkey',
    'db_key',
    'databasekey',
    'database_key',
    'clientkey',
    'client_key',
    'aws_secret_access_key',
    'password',
    'passwd',
    'pass',
    'pwd',
    'private_key',
    'privatekey',
    'priv_key',
    'privkey',
    'secret',
    'secrete',
    'secreto',
    'token',
    'contrasena',
    'contraseña',
    'cred',
    'credential',
    'credentials',
)
FALSE_POSITIVES = {
    '""):',
    '"\'',
    '")',
    '"replace',
    '"this',
    'passes',
    'passing',
    '$(shell',
    "'\"",
    "''):",
    "')",
    "'dummy",
    "'replace",
    "'this",
    '(nsstring',
    '-default}',
    '::',
    '=',
    '<keyalg>',
    '\\"$(shell',
    '${',
    '\\k.*"',
    "\\k.*'",
    '`cat',
    '`grep',
    '`sudo',
    'account_password',
    'api_key',
    'disable',
    'dummy_secret',
    'dummy_value',
    'false',
    'false):',
    'false,',
    'false;',
    'login_password',
    'none',
    'none,',
    'none}',
    'nopasswd',
    'not',
    'not_real_key',
    'null',
    'null,',
    'null.*"',
    "null.*'",
    'null;',
    'pass)',
    'password)',
    'password))',
    'password,',
    'password},',
    'prompt',
    'redacted',
    'some_key',
    'str',
    'str_to_sign',
    'string',
    'string)',
    'string,',
    'string;',
    'string?',
    'string?)',
    'string}',
    'string}}',
    'test-access-key',
    'thisisnottherealsecret',
    'todo',
    'true',
    'true):',
    'true,',
    'true;',
    'undef',
    'undef,',
    '{',
    '{{',
}
AFFIX_REGEX = r'[a-zA-Z0-9._\-]*'
DENYLIST_REGEX = r'({prefix})('.format(prefix=AFFIX_REGEX) \
    + r'|'.join(DENYLIST) + r')({suffix})'.format(suffix=AFFIX_REGEX)
# Non-greedy match
OPTIONAL_WHITESPACE = r'\s*?'
OPTIONAL_NON_WHITESPACE = r'[^\s]{0,50}?'
QUOTE = r'[\"\']'
SECRET = r'""|\'\'|[^\'"\s]+'
SECRET_INTO_TAG = r'[^<\s]+'
# Includes ], ', " as closing
CLOSING = r'[]\'"]{0,2}'

# XML credentials keyword in tag
XML_KEYWORD_IN_TAG_REGEX = re.compile(
    # e.g. <password>foo</password>
    r'<{whitespace}({denylist}){whitespace}>{whitespace}({secret})'.format(
        denylist=DENYLIST_REGEX,
        whitespace=OPTIONAL_WHITESPACE,
        secret=SECRET_INTO_TAG,
    ),
)
# XML credentials keyword in name prop
XML_KEYWORD_IN_NAME_PROP_REGEX = re.compile(
    # e.g. <tag name="password" value="foo" />
    r'<[^>]+ name{whitespace}={whitespace}({quote}){whitespace}({denylist}){whitespace}({quote}) value{whitespace}={whitespace}({quote}){whitespace}({secret}){whitespace}({quote})'.format(  # noqa: E501
        denylist=DENYLIST_REGEX,
        quote=QUOTE,
        whitespace=OPTIONAL_WHITESPACE,
        secret=SECRET,
    ),
)
# XML credentials keyword
XML_KEYWORD_VALUE_REGEX = re.compile(
    # e.g. <tag name="password">foo</tag>
    r'<[^>]+ name{whitespace}={whitespace}({quote}){whitespace}({denylist}){whitespace}({quote}){whitespace}>{whitespace}({secret})'.format(  # noqa: E501
        denylist=DENYLIST_REGEX,
        quote=QUOTE,
        whitespace=OPTIONAL_WHITESPACE,
        secret=SECRET_INTO_TAG,
    ),
)
# XML credentials keyword in name prop
XML_KEYWORD_IN_NAME_PROP_REV_REGEX = re.compile(
    # e.g. <tag value="foo" name="password" />
    r'<[^>]+ value{whitespace}={whitespace}({quote}){whitespace}({secret}){whitespace}({quote}) name{whitespace}={whitespace}({quote}){whitespace}({denylist}){whitespace}({quote})'.format(  # noqa: E501
        denylist=DENYLIST_REGEX,
        quote=QUOTE,
        whitespace=OPTIONAL_WHITESPACE,
        secret=SECRET,
    ),
)
XML_KEYWORD_VALUE_IN_PROP_REGEX = re.compile(
    # e.g. <password value="foo" />
    r'<{whitespace}({denylist}) value{whitespace}={whitespace}({quote}){whitespace}({secret}){whitespace}({quote})'.format(  # noqa: E501
        denylist=DENYLIST_REGEX,
        quote=QUOTE,
        whitespace=OPTIONAL_WHITESPACE,
        secret=SECRET,
    ),
)
FOLLOWED_BY_EQUAL_SIGNS_QUOTES_REQUIRED_REGEX = re.compile(
    # e.g. my_password = "bar"
    # e.g. my_password = 'bar'
    r'({denylist})({closing})?{whitespace}={whitespace}({quote})({secret})({quote})'.format(
        denylist=DENYLIST_REGEX,
        closing=CLOSING,
        quote=QUOTE,
        whitespace=OPTIONAL_WHITESPACE,
        secret=SECRET,
    ),
)


DENYLIST_REGEX_TO_GROUP = {
    XML_KEYWORD_IN_TAG_REGEX: 5,
    XML_KEYWORD_IN_NAME_PROP_REGEX: 8,
    XML_KEYWORD_VALUE_REGEX: 7,
    XML_KEYWORD_IN_NAME_PROP_REV_REGEX: 2,
    XML_KEYWORD_VALUE_IN_PROP_REGEX: 6,
    FOLLOWED_BY_EQUAL_SIGNS_QUOTES_REQUIRED_REGEX: 7,
}


class KeywordXMLDetector(BasePlugin):
    """
    Scans for secret-sounding variable names.
    This checks if denylisted keywords are present in the analyzed string.
    """
    secret_type = 'Secret XML Keyword'

    def __init__(self, keyword_exclude: Optional[str] = None) -> None:
        self.keyword_exclude = None
        if keyword_exclude:
            self.keyword_exclude = re.compile(
                keyword_exclude,
                re.IGNORECASE,
            )

    def analyze_string(
        self,
        string: str,
        denylist_regex_to_group: Optional[Dict[Pattern, int]] = None,
    ) -> Generator[str, None, None]:
        if self.keyword_exclude and self.keyword_exclude.search(string):
            return

        if denylist_regex_to_group is None:
            attempts = [
                DENYLIST_REGEX_TO_GROUP,
            ]
        else:
            attempts = [denylist_regex_to_group]

        has_results = False
        for denylist_regex_to_group in attempts:
            for denylist_regex, group_number in denylist_regex_to_group.items():
                match = denylist_regex.search(string)
                if match:
                    has_results = True
                    yield match.group(group_number)

            if has_results:
                break

    def analyze_line(
        self,
        filename: str,
        line: str,
        line_number: int = 0,
        **kwargs: Any,
    ) -> Set[PotentialSecret]:
        filetype = determine_file_type(filename)

        if filetype == FileType.XML:
            return super().analyze_line(
                filename=filename,
                line=line,
                line_number=line_number,
                denylist_regex_to_group=DENYLIST_REGEX_TO_GROUP,
            )

    def json(self) -> Dict[str, Any]:
        return {
            'keyword_exclude': (
                self.keyword_exclude.pattern
                if self.keyword_exclude
                else ''
            ),
            **super().json(),
        }
