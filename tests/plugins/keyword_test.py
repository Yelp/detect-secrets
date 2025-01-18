import base64
from random import randint

import pytest

from detect_secrets.core.scan import scan_line
from detect_secrets.plugins.keyword import KeywordDetector
from detect_secrets.settings import transient_settings


COMMON_SECRET = 'm{{h}o)p${e]nob(ody[finds>-_$#thisone}}'
WHITES_SECRET = 'value with quotes and spaces'
LETTER_SECRET = 'A,.:-¨@*¿?!'
SYMBOL_SECRET = ',.:-¨@*¿?!'

LONG_LINE = '<img src="data:image/png;base64,{}\n"\n>'.format(base64.b64encode((str(randint(0, 9)) * 24000).encode()))  # noqa: E501

CONFIG_TEST_CASES = [
    ('password = "{}"'.format(WHITES_SECRET), WHITES_SECRET),
    ('password_super_secure = "{}"'.format(WHITES_SECRET), WHITES_SECRET),  # Suffix
    ('my_password_super_secure = "{}"'.format(WHITES_SECRET), WHITES_SECRET),  # Prefix/suffix
    ('apikey = {}'.format(COMMON_SECRET), COMMON_SECRET),
    ("api_key: '{}'".format(WHITES_SECRET), WHITES_SECRET),
    ('aws_secret_access_key: {}'.format(WHITES_SECRET), WHITES_SECRET),
    ('db_pass: {},'.format(COMMON_SECRET), COMMON_SECRET),      # Last character is ignored
    ('passwd: {}`'.format(COMMON_SECRET), COMMON_SECRET),       # Last character is ignored
    ('pass: {}`'.format(COMMON_SECRET), COMMON_SECRET),       # Last character is ignored
    ('private_key: {}"'.format(COMMON_SECRET), COMMON_SECRET),  # Last character is ignored
    ("secret: {}'".format(COMMON_SECRET), COMMON_SECRET),       # Last character is ignored
    ('secrete "{}";'.format(COMMON_SECRET), COMMON_SECRET),
    ('if (apikey == "{}") {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('if (api_key != "{}") {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('if (aws_secret_access_key === "{}") {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('if (db_pass !== "{}") {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('if ("{}" == password) {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('if ("{}" == my_super_password) {{'.format(COMMON_SECRET), COMMON_SECRET),     # Prefix
    ('if ("{}" != passwd) {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('if ("{}" != pass) {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('if ("{}" === private_key) {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('if ("{}" !== secret) {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('secrete = {}'.format(LETTER_SECRET), LETTER_SECRET),   # All symbols are allowed
    ('password = {}'.format(SYMBOL_SECRET), None),  # At least 1 alphanumeric character is required
    ('api_key = ""', None),  # Nothing in the quotes
    ("secret: ''", None),   # Nothing in the quotes
    ('password = "somefakekey"', None),  # 'fake' in the secret
    ('password: ${link}', None),        # Has a ${ followed by a }
    ('some_key = "real_secret"', None),  # We cannot make 'key' a Keyword, too noisy)
    ('private_key "hopenobodyfindsthisone\';', None),   # Double-quote does not match single-quote)
    (LONG_LINE, None),  # Long line test
]

GOLANG_TEST_CASES = [
    ('apikey := "{}"'.format(COMMON_SECRET), COMMON_SECRET),
    ("api_key := '{}'".format(COMMON_SECRET), COMMON_SECRET),
    ('aws_secret_access_key := `{}`'.format(COMMON_SECRET), COMMON_SECRET),
    ('db_pass := {}'.format(COMMON_SECRET), COMMON_SECRET),
    ('db_pass_secure := {}'.format(COMMON_SECRET), COMMON_SECRET),  # Suffix
    ('passwd := {},'.format(COMMON_SECRET), COMMON_SECRET),         # Last character is ignored
    ('pass := {},'.format(COMMON_SECRET), COMMON_SECRET),         # Last character is ignored
    ("private_key := {}'".format(COMMON_SECRET), COMMON_SECRET),    # Last character is ignored
    ('secret := {}"'.format(COMMON_SECRET), COMMON_SECRET),         # Last character is ignored
    ('password := {}`'.format(COMMON_SECRET), COMMON_SECRET),       # Last character is ignored
    ('if ("{}" == passwd) {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('if ("{}" == pass) {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('if ("{}" === private_key) {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('if ("{}" != secret) {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('if ("{}" !== password) {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('if ("{}" !== my_password_sec) {{'.format(COMMON_SECRET), COMMON_SECRET),    # Prefix/suffix
    ('apikey = "{}"'.format(COMMON_SECRET), COMMON_SECRET),
    ("api_key = '{}'".format(COMMON_SECRET), COMMON_SECRET),
    ('aws_secret_access_key = `{}`'.format(COMMON_SECRET), COMMON_SECRET),
    ('db_pass = {}'.format(COMMON_SECRET), COMMON_SECRET),
    ('password = {},'.format(COMMON_SECRET), COMMON_SECRET),        # Last character is ignored
    ("passwd = {}'".format(COMMON_SECRET), COMMON_SECRET),          # Last character is ignored
    ("pass = {}'".format(COMMON_SECRET), COMMON_SECRET),          # Last character is ignored
    ('private_key = {}"'.format(COMMON_SECRET), COMMON_SECRET),     # Last character is ignored
    ('secret = {}`'.format(COMMON_SECRET), COMMON_SECRET),          # Last character is ignored
    ('secrete = "{}"'.format(COMMON_SECRET), COMMON_SECRET),
    ('if (apikey == "{}") {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('if (api_key === "{}") {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('if (aws_secret_access_key != "{}") {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('if (db_pass !== "{}") {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('password "{}";'.format(COMMON_SECRET), COMMON_SECRET),
    ('secrete := {}'.format(LETTER_SECRET), LETTER_SECRET),   # All symbols are allowed
    ('password :={}'.format(SYMBOL_SECRET), None),  # At least 1 alphanumeric character is required
    ('api_key = ""', None),    # Nothing in the quotes
    ("secret := ''", None),    # Nothing in the quotes
    ('password := "somefakekey"', None),    # 'fake' in the secret
    ('some_key = "real_secret"', None),     # We cannot make 'key' a Keyword, too noisy)
    ('private_key "hopenobodyfindsthisone\';', None),  # Double-quote does not match single-quote)
    ('password: real_key', None),
    ('password: "real_key"', None),
    (LONG_LINE, None),  # Long line test
]

COMMON_C_TEST_CASES = [
    ('apikey = "{}";'.format(COMMON_SECRET), COMMON_SECRET),
    ('if (secret == "{}")'.format(COMMON_SECRET), COMMON_SECRET),   # Comparison
    ('if (db_pass != "{}")'.format(COMMON_SECRET), COMMON_SECRET),  # Comparison
    ('password = @"{}";'.format(COMMON_SECRET), COMMON_SECRET),
    ('my_password_secure = @"{}";'.format(COMMON_SECRET), COMMON_SECRET),   # Prefix/suffix
    ('secrete[] = "{}";'.format(COMMON_SECRET), COMMON_SECRET),
    ('char secrete[25] = "{}";'.format(COMMON_SECRET), COMMON_SECRET),
    ('secrete = "{}"'.format(LETTER_SECRET), LETTER_SECRET),    # All symbols are allowed
    ('password = "{}"'.format(SYMBOL_SECRET), None),  # At least 1 alphanumeric char is required
    ("api_key = '{}';".format(COMMON_SECRET), None),                 # Double quotes required
    ("aws_secret_access_key = @'{}';".format(COMMON_SECRET), None),  # Double quotes required
    ("db_pass[] = '{}';".format(COMMON_SECRET), None),  # Double quotes required
    ('passwd = {};'.format(COMMON_SECRET), None),       # Double quotes required
    ('pass = {};'.format(COMMON_SECRET), None),       # Double quotes required
    ('private_key = {};'.format(COMMON_SECRET), None),  # Double quotes required
    ('secret[] = {};'.format(COMMON_SECRET), None),     # Double quotes required
    ('api_key = ""', None),                 # Nothing in the quotes
    ('password = "somefakekey"', None),     # 'fake' in the secret
    ('password[] = ${link}', None),         # Has a ${ followed by a }
    ('some_key = "real_secret"', None),     # We cannot make 'key' a Keyword, too noisy)
    (LONG_LINE, None),  # Long line test
]

C_PLUS_PLUS_TEST_CASES = [
    ('apikey = "{}";'.format(COMMON_SECRET), COMMON_SECRET),
    ('my_password_secure = "{}";'.format(COMMON_SECRET), COMMON_SECRET),  # Prefix and suffix
    ('password = {}'.format(COMMON_SECRET), None),  # Secret without quotes
    ('if (secret == "{}")'.format(COMMON_SECRET), COMMON_SECRET),   # Comparison
    ('if (db_pass != "{}")'.format(COMMON_SECRET), COMMON_SECRET),  # Comparison
    ('std::string secret("{}");'.format(COMMON_SECRET), COMMON_SECRET),
    ('secrete.assign("{}",17);'.format(COMMON_SECRET), COMMON_SECRET),
    ('api_key = ""', None),                 # Nothing in the quotes
    ('password = "somefakekey"', None),     # 'fake' in the secret
    ('password = ${link}', None),           # Has a ${ followed by a }
    ('some_key = "real_secret"', None),     # We cannot make 'key' a Keyword, too noisy)
]

QUOTES_REQUIRED_TEST_CASES = [
    ('apikey: "{}"'.format(COMMON_SECRET), COMMON_SECRET),
    ('apikey_myservice: "{}"'.format(COMMON_SECRET), COMMON_SECRET),    # Suffix
    ('api_key: `{}`'.format(COMMON_SECRET), COMMON_SECRET),
    ("aws_secret_access_key: '{}'".format(COMMON_SECRET), COMMON_SECRET),
    ("db_pass: '{}'".format(LETTER_SECRET), LETTER_SECRET),  # All symbols are allowed
    ("password: '{}'".format(SYMBOL_SECRET), None),  # At least 1 alphanumeric character is required
    ('if ("{}" == passwd) {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('if ("{}" == pass) {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('if ("{}" === private_key) {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('if ("{}" === my_private_key) {{'.format(COMMON_SECRET), COMMON_SECRET),   # Prefix
    ('if ("{}" != secret) {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('if ("{}" !== password) {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('secrete = "{}"'.format(COMMON_SECRET), COMMON_SECRET),
    ('if (apikey == "{}") {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('if (api_key === "{}") {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('if (aws_secret_access_key != "{}") {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('if (db_pass !== "{}") {{'.format(COMMON_SECRET), COMMON_SECRET),
    ('password "{}";'.format(COMMON_SECRET), COMMON_SECRET),
    ('password = {}'.format(COMMON_SECRET), None),  # Secret without quotes
    ('password = "{}"'.format(COMMON_SECRET), COMMON_SECRET),
    ('password => "{}"'.format(COMMON_SECRET), COMMON_SECRET),
    ('api_key = ""', None),              # Nothing in the quotes
    ("secret: ''", None),                # Nothing in the quotes
    ('password: ${link}', None),         # Has a ${ followed by a }
    ('some_key = "real_secret"', None),  # We cannot make 'key' a Keyword, too noisy)
    ('private_key "hopenobodyfindsthisone\';', None),  # Double-quote does not match single-quote)
    (LONG_LINE, None),  # Long line test
    ('password => ""', None),
    ('password => {}'.format(COMMON_SECRET), None),
]


def parse_test_cases(test_cases):
    for file_extension, test_case in test_cases:
        for item in test_case:
            line, expected_secret = item
            yield file_extension, line, expected_secret


@pytest.mark.parametrize(
    'file_extension, line, expected_secret',
    (
        parse_test_cases([
            ('conf', CONFIG_TEST_CASES),
            ('go', GOLANG_TEST_CASES),
            ('m', COMMON_C_TEST_CASES),
            ('c', COMMON_C_TEST_CASES),
            ('cs', COMMON_C_TEST_CASES),
            ('cls', QUOTES_REQUIRED_TEST_CASES),
            ('java', QUOTES_REQUIRED_TEST_CASES),
            ('py', QUOTES_REQUIRED_TEST_CASES),
            ('pyi', QUOTES_REQUIRED_TEST_CASES),
            ('js', QUOTES_REQUIRED_TEST_CASES),
            ('swift', QUOTES_REQUIRED_TEST_CASES),
            ('tf', QUOTES_REQUIRED_TEST_CASES),
            (None, QUOTES_REQUIRED_TEST_CASES),
        ])
    ),
)
def test_keyword(file_extension, line, expected_secret):
    if not file_extension:
        secrets = list(scan_line(line))
    else:
        secrets = list(
            KeywordDetector(keyword_exclude='.*fake.*').analyze_line(
                filename='mock_filename.{}'.format(file_extension),
                line=line,
            ),
        )
    if expected_secret:
        assert secrets[0].secret_value == expected_secret
    else:
        assert not secrets


@pytest.fixture(autouse=True)
def use_keyword_detector():
    with transient_settings({
        'plugins_used': [{
            'name': 'KeywordDetector',
        }],
    }):
        yield
