"""
This code was extracted in part from
https://github.com/PyCQA/bandit. Using similar heuristic logic,
we adapted it to fit our plugin infrastructure, to create an organized,
concerted effort in detecting all type of secrets in code.

Copyright (c) 2014 Hewlett-Packard Development Company, L.P.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
import re

from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.protection import hide_secret, hide_line
from detect_secrets.plugins.base import BasePlugin
from detect_secrets.plugins.base import classproperty
from detect_secrets.plugins.common.filetype import determine_file_type
from detect_secrets.plugins.common.filetype import FileType
from detect_secrets.plugins.common.filters import get_aho_corasick_helper
from detect_secrets.plugins.common.filters import is_sequential_string

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
VARIABLE_REGEX = r'[a-zA-Z0-9._-]*'
DENYLIST_REGEX = r'({variable})('.format(variable=VARIABLE_REGEX) + r'|'.join(DENYLIST) + r')({variable})'.format(variable=VARIABLE_REGEX)
# Non-greedy match
OPTIONAL_WHITESPACE = r'\s*?'
OPTIONAL_NON_WHITESPACE = r'[^\s]*?'
QUOTE = r'[\"]'
SECRET = r'""|\'\'|[^\'"\s]+'
SECRET_INTO_TAG = r'[^<]+'
# Includes ], ', " as closing
CLOSING = r'[]\'"]{0,2}'

# XML credentials keyword in tag
XML_KEYWORD_IN_TAG_REGEX = re.compile(
    # e.g. <password>foo</password>
    r'<({denylist})>{whitespace}({secret})'.format(
        denylist=DENYLIST_REGEX,
        whitespace=OPTIONAL_WHITESPACE,
        secret=SECRET_INTO_TAG,
    ),
)

# XML credentials keyword in name prop
XML_KEYWORD_IN_NAME_PROP_REGEX = re.compile(
    # e.g. <tag name="password" value="foo" />
    r'<[^>]+ name=({quote}){whitespace}({denylist}){whitespace}({quote}) value=({quote}){whitespace}({secret}){whitespace}({quote})'.format(
        denylist=DENYLIST_REGEX,
        quote=QUOTE,
		whitespace=OPTIONAL_WHITESPACE,
        secret=SECRET,
    ),
)

# XML credentials keyword
XML_KEYWORD_VALUE_REGEX = re.compile(
    # e.g. <tag name="password">foo</tag>
    r'<[^>]+ name=({quote}){whitespace}({denylist}){whitespace}({quote}){whitespace}>({secret})'.format(
        denylist=DENYLIST_REGEX,
        quote=QUOTE,
		whitespace=OPTIONAL_WHITESPACE,
        secret=SECRET_INTO_TAG,
    ),
)

# XML credentials keyword in name prop
XML_KEYWORD_IN_NAME_PROP_REV_REGEX = re.compile(
    # e.g. <tag value="foo" name="password" />
    r'<[^>]+ value=({quote}){whitespace}({secret}){whitespace}({quote}) name=({quote}){whitespace}({denylist}){whitespace}({quote})'.format(
        denylist=DENYLIST_REGEX,
        quote=QUOTE,
		whitespace=OPTIONAL_WHITESPACE,
        secret=SECRET,
    ),
)

# tag=password value=foo
XML_KEYWORD_VALUE_IN_PROP_REGEX = re.compile(
    # e.g. <password value="foo" />
    r'<({denylist}) value=({quote}){whitespace}({secret}){whitespace}({quote})'.format(
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

    @classproperty
    def default_options(cls):
        return {
            #'keyword_exclude': None,
        }

    @property
    def __dict__(self):
        output = {
            'keyword_exclude': self.keyword_exclude,
        }
        output.update(super(KeywordXMLDetector, self).__dict__)

        return output

    def __init__(self, keyword_exclude=None, exclude_lines_regex=None, automaton=None, **kwargs):
        false_positive_heuristics = [
            get_aho_corasick_helper(automaton),
            is_sequential_string,
        ]

        super(KeywordXMLDetector, self).__init__(
            exclude_lines_regex=exclude_lines_regex,
            false_positive_heuristics=false_positive_heuristics,
            **kwargs
        )

        self.keyword_exclude = None
        if keyword_exclude:
            self.keyword_exclude = re.compile(
                keyword_exclude,
                re.IGNORECASE,
            )

        self.automaton = automaton

    def analyze_string_content(self, string, line_num, filename):
        output = {}
        if (
            self.keyword_exclude
            and self.keyword_exclude.search(string)
        ):
            return output
        for plain_secret, hidden_secret, hidden_line in self.secret_generator(
            string,
            filetype=determine_file_type(filename),
        ):
            if self.is_secret_false_positive(plain_secret):
                continue
            secret = PotentialSecret(
                self.secret_type,
                filename,
                plain_secret,
                line_num,
                hidden_secret,
                hidden_line
            )
            output[secret] = secret

        return output

    def secret_generator(self, string, filetype):
        lowered_string = string.lower()

        if filetype == FileType.XML:
            denylist_regex_to_group = DENYLIST_REGEX_TO_GROUP

            for denylist_regex, group_number in denylist_regex_to_group.items():
                match = denylist_regex.search(lowered_string)
                if match:
                    lowered_secret = match.group(group_number)

                    index = match.start(group_number)
                    hidden_secret = hide_secret(string[index:index + len(lowered_secret)])
                    hidden_line = hide_line(hidden_secret, string, index)

                    # ([^\s]+) guarantees lowered_secret is not ''
                    if not probably_false_positive(
                        lowered_secret,
                        filetype=filetype,
                    ):
                        yield lowered_secret, hidden_secret, hidden_line


def probably_false_positive(lowered_secret, filetype):
    if not lowered_secret:
        return False

    if (
        any(
            false_positive in lowered_secret
            for false_positive in (
                '/etc/',
                'fake',
                'forgot',
            )
        ) or lowered_secret in FALSE_POSITIVES
        # For e.g. private_key "some/dir/that/is/not/a/secret";
        or lowered_secret.count('/') >= 3
        # For e.g. "secret": "{secret}"
        or (
            lowered_secret[0] == '{'
            and lowered_secret[-1] == '}'
        ) 
    ):
        return True

    # Heuristic for no function calls
    try:
        if (
            lowered_secret.index('(') < lowered_secret.index(')')
        ):
            return True
    except ValueError:
        pass

    # Heuristic for e.g. request.json_body['hey']
    try:
        if (
            lowered_secret.index('[') < lowered_secret.index(']')
        ):
            return True
    except ValueError:
        pass

    # Heuristic for e.g. ${link}
    try:
        if (
            lowered_secret.index('${') < lowered_secret.index('}')
        ):
            return True
    except ValueError:
        pass

    return False
