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
    'keypass',
	'token',
    'contrasena',
    'contraseña',
)
FALSE_POSITIVES = {
    '""):',
    '"\'',
    '"replace',
    '"this',
    'passes',
    'passing',
    '$(shell',
    "'\"",
    "''):",
    "'dummy",
    "'replace",
    "'this",
    '(nsstring',
    '-default}',
    '::',
    '<%=',
    'secretName',
    '<aws_secret_access_key>',
    '<input',
    '<password>',
    '<redacted>',
    '>',
    '=',
    '\\"$(shell',
    '\\k.*"',
    "\\k.*'",
    '`cat',
    '`grep',
    '`sudo',
    'account_password',
    'commit',
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
# Includes ], ', " as closing
CLOSING = r'[]\'"]{0,2}'
VARIABLE_REGEX = r'[a-zA-Z0-9_-]*'
DENYLIST_REGEX = r'(' + r'|'.join(DENYLIST) + r')({variable})?'.format(variable=VARIABLE_REGEX)
DENYLIST_REGEX_WITH_PREV = r'({variable})('.format(variable=VARIABLE_REGEX) + r'|'.join(DENYLIST) + r')({variable})'.format(variable=VARIABLE_REGEX)
# Non-greedy match
OPTIONAL_WHITESPACE = r'\s*?'
OPTIONAL_NON_WHITESPACE = r'[^\s]*?'
QUOTE = r'[\'"]'
SECRET = r'""|\'\'|[^\'"\s]+'
SQUARE_BRACKETS = r'(\[\])'

# Pascal | GOLANG
FOLLOWED_BY_COLON_EQUAL_SIGNS_REGEX = re.compile(
    # e.g. my_password := "bar"
    r'({denylist})({closing})?{whitespace}:=?{whitespace}({quote})({secret})({quote})'.format(
        denylist=DENYLIST_REGEX,
        closing=CLOSING,
        quote=QUOTE,
        whitespace=OPTIONAL_WHITESPACE,
        secret=SECRET,
    ),
)

# YAML y .ini
FOLLOWED_BY_COLON_REGEX = re.compile(
    # e.g. api_key: foo
    r'({denylist})({closing})?:{whitespace}({secret})'.format(
        denylist=DENYLIST_REGEX,
        closing=CLOSING,
        quote=QUOTE,
        whitespace=OPTIONAL_WHITESPACE,
        secret=SECRET,
    ),
)

# YAML y .ini
FOLLOWED_BY_COLON_QUOTES_REQUIRED_REGEX = re.compile(
    # e.g. api_key: "foo"
    r'({denylist})({closing})?:({whitespace})({quote})({secret})({quote})'.format(
        denylist=DENYLIST_REGEX,
        closing=CLOSING,
        quote=QUOTE,
        whitespace=OPTIONAL_WHITESPACE,
        secret=SECRET,
    ),
)

# Objective-C
FOLLOWED_BY_EQUAL_SIGNS_OPTIONAL_BRACKETS_OPTIONAL_AT_SIGN_QUOTES_REQUIRED_REGEX = re.compile(
    # e.g. my_password = "bar"
    # e.g. my_password = @"bar"
    # e.g. my_password[] = "bar";
    r'({denylist})({square_brackets})?{optional_whitespace}={optional_whitespace}(@)?(")({secret})(")'.format(  # noqa: E501
        denylist=DENYLIST_REGEX,
        square_brackets=SQUARE_BRACKETS,
        optional_whitespace=OPTIONAL_WHITESPACE,
        secret=SECRET,
    ),
)

# Properties y .ini
FOLLOWED_BY_EQUAL_SIGNS_REGEX = re.compile(
    # e.g. my_password = bar
    r'({denylist})({closing})?{whitespace}={whitespace}({quote}?)({secret})'.format(
        denylist=DENYLIST_REGEX,
        closing=CLOSING,
        quote=QUOTE,
        whitespace=OPTIONAL_WHITESPACE,
        secret=SECRET,
    ),
)

# Properties y .ini | C/C++/C# | Java | Bash | Powershell | Python | Swift | JS | TERRAFORM
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

FOLLOWED_BY_COMPARATION_QUOTES_REQUIRED_REGEX = re.compile(
    # e.g. my_password == "bar" or my_password != "bar" or my_password === "bar" or my_password !== "bar"
    # e.g. my_password == 'bar' or my_password != 'bar' or my_password === 'bar' or my_password !== 'bar'
    r'({denylist})({closing})?{whitespace}[!=]{{2,3}}{whitespace}({quote})({secret})({quote})'.format(
        denylist=DENYLIST_REGEX,
        closing=CLOSING,
        quote=QUOTE,
        whitespace=OPTIONAL_WHITESPACE,
        secret=SECRET,
    ),
)

FOLLOWED_BY_REV_COMPARATION_QUOTES_REQUIRED_REGEX = re.compile(
    # e.g. "bar" == my_password or "bar" != my_password or "bar" === my_password or "bar" !== my_password
    # e.g. 'bar' == my_password or 'bar' != my_password or 'bar' === my_password or 'bar' !== my_password
    r'({quote})({secret})({quote}){whitespace}[!=]{{2,3}}{whitespace}({denylist})'.format(
        denylist=DENYLIST_REGEX_WITH_PREV,
        quote=QUOTE,
        whitespace=OPTIONAL_WHITESPACE,
        secret=SECRET,
    ),
)

# General
FOLLOWED_BY_QUOTES_AND_SEMICOLON_REGEX = re.compile(
    # e.g. private_key "something";
    r'({denylist}){nonWhitespace}{whitespace}({quote})({secret})({quote});'.format(
        denylist=DENYLIST_REGEX,
        nonWhitespace=OPTIONAL_NON_WHITESPACE,
        quote=QUOTE,
        whitespace=OPTIONAL_WHITESPACE,
        secret=SECRET,
    ),
)

DENYLIST_REGEX_TO_GROUP = {
    FOLLOWED_BY_COLON_QUOTES_REQUIRED_REGEX: 7,
    FOLLOWED_BY_COLON_REGEX: 5,
    FOLLOWED_BY_EQUAL_SIGNS_QUOTES_REQUIRED_REGEX: 6,
    FOLLOWED_BY_QUOTES_AND_SEMICOLON_REGEX: 5,
    FOLLOWED_BY_EQUAL_SIGNS_REGEX: 6,
}
GOLANG_DENYLIST_REGEX_TO_GROUP = {
    FOLLOWED_BY_COLON_EQUAL_SIGNS_REGEX: 6,
    FOLLOWED_BY_EQUAL_SIGNS_QUOTES_REQUIRED_REGEX: 6,
    FOLLOWED_BY_QUOTES_AND_SEMICOLON_REGEX: 5,
    FOLLOWED_BY_COMPARATION_QUOTES_REQUIRED_REGEX: 6,
    FOLLOWED_BY_REV_COMPARATION_QUOTES_REQUIRED_REGEX: 2,
}
OBJECTIVE_C_DENYLIST_REGEX_TO_GROUP = {
    FOLLOWED_BY_EQUAL_SIGNS_OPTIONAL_BRACKETS_OPTIONAL_AT_SIGN_QUOTES_REQUIRED_REGEX: 8,
    FOLLOWED_BY_COMPARATION_QUOTES_REQUIRED_REGEX: 6,
    FOLLOWED_BY_REV_COMPARATION_QUOTES_REQUIRED_REGEX: 2,
}
YML_DENYLIST_REGEX_TO_GROUP = {
    FOLLOWED_BY_COLON_QUOTES_REQUIRED_REGEX: 7,
    FOLLOWED_BY_COLON_REGEX: 5,
    FOLLOWED_BY_EQUAL_SIGNS_QUOTES_REQUIRED_REGEX: 6,
    FOLLOWED_BY_EQUAL_SIGNS_REGEX: 6,
    FOLLOWED_BY_QUOTES_AND_SEMICOLON_REGEX: 5,
}
PROPERTIES_DENYLIST_REGEX_TO_GROUP = {
    FOLLOWED_BY_EQUAL_SIGNS_QUOTES_REQUIRED_REGEX: 6,
    FOLLOWED_BY_EQUAL_SIGNS_REGEX: 6,
    FOLLOWED_BY_QUOTES_AND_SEMICOLON_REGEX: 5,
}
QUOTES_REQUIRED_DENYLIST_REGEX_TO_GROUP = {
    FOLLOWED_BY_EQUAL_SIGNS_QUOTES_REQUIRED_REGEX: 6,
    FOLLOWED_BY_QUOTES_AND_SEMICOLON_REGEX: 5,
    FOLLOWED_BY_COMPARATION_QUOTES_REQUIRED_REGEX: 6,
    FOLLOWED_BY_REV_COMPARATION_QUOTES_REQUIRED_REGEX: 2,
}

QUOTES_REQUIRED_FILETYPES = {
    FileType.CLS,
    FileType.JAVA,
    FileType.JAVASCRIPT,
    FileType.PHP,
    FileType.PYTHON,
    FileType.SWIFT,
    FileType.TERRAFORM,
    FileType.C,
    FileType.CPP,
    FileType.CSHARP,
    FileType.BASH,
    FileType.POWERSHELL,
}


class KeywordDetector(BasePlugin):
    """
    Scans for secret-sounding variable names.

    This checks if denylisted keywords are present in the analyzed string.
    """
    secret_type = 'Secret Keyword'

    @classproperty
    def default_options(cls):
        return {
            'keyword_exclude': None,
        }

    @property
    def __dict__(self):
        output = {
            'keyword_exclude': self.keyword_exclude,
        }
        output.update(super(KeywordDetector, self).__dict__)

        return output

    def __init__(self, keyword_exclude=None, exclude_lines_regex=None, automaton=None, **kwargs):
        false_positive_heuristics = [
            get_aho_corasick_helper(automaton),
            is_sequential_string,
        ]

        super(KeywordDetector, self).__init__(
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

        if filetype in QUOTES_REQUIRED_FILETYPES:
            denylist_regex_to_group = QUOTES_REQUIRED_DENYLIST_REGEX_TO_GROUP
        elif filetype == FileType.GO:
             denylist_regex_to_group = GOLANG_DENYLIST_REGEX_TO_GROUP
        elif filetype == FileType.OBJECTIVE_C:
            denylist_regex_to_group = OBJECTIVE_C_DENYLIST_REGEX_TO_GROUP
        elif filetype == FileType.YAML or filetype == FileType.INI:
            denylist_regex_to_group = YML_DENYLIST_REGEX_TO_GROUP
        elif filetype == FileType.PROPERTIES or filetype == FileType.INI:
            denylist_regex_to_group = PROPERTIES_DENYLIST_REGEX_TO_GROUP
        else:
            denylist_regex_to_group = DENYLIST_REGEX_TO_GROUP

        if filetype != FileType.XML:
            for denylist_regex, group_number in denylist_regex_to_group.items():
                match = denylist_regex.search(lowered_string)
                if match:
                    lowered_secret = match.group(group_number)

                    index = match.start(group_number)
                    hidden_secret = hide_secret(string[index:index + len(lowered_secret)])
                    hidden_line = hide_line(hidden_secret, string, index)
                    
                    # ([^\s]+) guarantees lowered_secret is not ''
                    if lowered_secret and not probably_false_positive(
                        lowered_secret,
                        filetype=filetype,
                    ):
                        yield lowered_secret, hidden_secret, hidden_line


def probably_false_positive(lowered_secret, filetype):
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
        ) or (
            filetype not in QUOTES_REQUIRED_FILETYPES
            and lowered_secret[0] == '$'
        ) or (
            filetype == FileType.EXAMPLE
            and lowered_secret[0] == '<'
            and lowered_secret[-1] == '>'
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
