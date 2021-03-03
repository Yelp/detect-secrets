import tempfile

import pytest

from detect_secrets.core.scan import scan_file
from detect_secrets.core.scan import scan_line
from detect_secrets.plugins.keyword import KeywordDetector
from detect_secrets.settings import transient_settings


FOLLOWED_BY_COLON_EQUAL_SIGNS_RE = {
    'negatives': {
        'quotes_required': [
            'theapikey := ""',  # Nothing in the quotes
            'theapikey := "somefakekey"',  # 'fake' in the secret
        ],
        'quotes_not_required': [
            'theapikeyforfoo := hopenobodyfindsthisone',  # Characters between apikey and :=
        ],
    },
    'positives': {
        'quotes_required': [
            'apikey := "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            'apikey :="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            'apikey  :=   "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            "apikey := 'm{{h}o)p${e]nob(ody[finds>-_$#thisone}}'",
            "apikey :='m{{h}o)p${e]nob(ody[finds>-_$#thisone}}'",
            'apikey:= "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            'apikey:="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            "apikey:= 'm{{h}o)p${e]nob(ody[finds>-_$#thisone}}'",
            "apikey:='m{{h}o)p${e]nob(ody[finds>-_$#thisone}}'",
            "apikey:=  'm{{h}o)p${e]nob(ody[finds>-_$#thisone}}'",
        ],
        'quotes_not_required': [
            'apikey := m{{h}o)p${e]nob(ody[finds>-_$#thisone}}',
            'apikey :=m{{h}o)p${e]nob(ody[finds>-_$#thisone}}',
            'apikey:= m{{h}o)p${e]nob(ody[finds>-_$#thisone}}',
            'apikey:=m{{h}o)p${e]nob(ody[finds>-_$#thisone}}',
        ],
    },
}
FOLLOWED_BY_COLON_RE = {
    'negatives': {
        'quotes_required': [
            'theapikey: ""',  # Nothing in the quotes
            'theapikey: "somefakekey"',  # 'fake' in the secret
        ],
        'quotes_not_required': [
            'theapikeyforfoo:hopenobodyfindsthisone',  # Characters between apikey and :
            'password: ${link}',  # Has a ${ followed by a }
        ],
    },
    'positives': {
        'quotes_required': [
            "'theapikey': 'm{{h}o)p${e]nob(ody[finds>-_$#thisone}}'",
            '"theapikey": "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            'apikey: "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            "apikey:  'm{{h}o)p${e]nob(ody[finds>-_$#thisone}}'",
        ],
        'quotes_not_required': [
            'apikey: m{{h}o)p${e]nob(ody[finds>-_$#thisone}}',
            'apikey:m{{h}o)p${e]nob(ody[finds>-_$#thisone}}',
            'theapikey:m{{h}o)p${e]nob(ody[finds>-_$#thisone}}',
        ],
    },
}
FOLLOWED_BY_EQUAL_SIGNS_OPTIONAL_BRACKETS_OPTIONAL_AT_SIGN_QUOTES_REQUIRED_REGEX = {
    'negatives': {
        'quotes_required': [
            'theapikey[] = ""',  # Nothing in the quotes
            'theapikey = @"somefakekey"',  # 'fake' in the secret
        ],
    },
    'positives': {
        'quotes_required': [
            'apikey = "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            'apikey ="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            'apikey  =   "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            'apikey = @"m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            'apikey =@"m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            'apikey  =   @"m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            'apikey[]= "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            'apikey[]="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
        ],
    },
}
FOLLOWED_BY_EQUAL_SIGNS_RE = {
    'negatives': {
        'quotes_required': [
            'some_key = "real_secret"',  # We cannot make 'key' a Keyword, too noisy
            'my_password = ""',  # Nothing in the quotes
            "my_password = ''",  # Nothing in the quotes
            'my_password = "fakesecret"',  # 'fake' in the secret
            'open(self, password = ""):',  # secrets is ""):
            'open(self, password = ""):',  # secrets is ""):
        ],
        'quotes_not_required': [
            'my_password = foo(hey)you',  # Has a ( followed by a )
            "my_password = request.json_body['hey']",  # Has a [ followed by a ]
            'my_password = True',  # 'True' is a known false-positive
            'login(username=username, password=password)',  # secret is password)
        ],
    },
    'positives': {
        'quotes_required': [
            'some_dict["secret"] = "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            'the_password= "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"\n',
            'the_password=\'m{{h}o)p${e]nob(ody[finds>-_$#thisone}}\'\n',
        ],
        'quotes_not_required': [
            "some_dict['secret'] = m{{h}o)p${e]nob(ody[finds>-_$#thisone}}",
            'my_password=m{{h}o)p${e]nob(ody[finds>-_$#thisone}}',
            'my_password= m{{h}o)p${e]nob(ody[finds>-_$#thisone}}',
            'my_password =m{{h}o)p${e]nob(ody[finds>-_$#thisone}}',
            'my_password = m{{h}o)p${e]nob(ody[finds>-_$#thisone}}',
            'my_password =m{{h}o)p${e]nob(ody[finds>-_$#thisone}}',
            'the_password=m{{h}o)p${e]nob(ody[finds>-_$#thisone}}\n',
        ],
    },
}
FOLLOWED_BY_QUOTES_AND_SEMICOLON_RE = {
    'negatives': {
        'quotes_required': [
            'private_key "";',  # Nothing in the quotes
            'private_key \'"no spaces\';',  # Has whitespace in the secret
            'private_key "fake";',  # 'fake' in the secret
            'private_key "some/dir/aint/a/secret";',  # 3 or more /
            'private_key "${FOO}";',  # Starts with ${ and ends with }
            'private_key "hopenobodyfindsthisone\';',  # Double-quote does not match single-quote
            'private_key \'hopenobodyfindsthisone";',  # Single-quote does not match double-quote
        ],
    },
    'positives': {
        'quotes_required': [
            'apikey "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}";',  # Double-quotes
            'fooapikeyfoo "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}";',  # Double-quotes
            'fooapikeyfoo"m{{h}o)p${e]nob(ody[finds>-_$#thisone}}";',  # Double-quotes
            'private_key \'m{{h}o)p${e]nob(ody[finds>-_$#thisone}}\';',  # Single-quotes
            'fooprivate_keyfoo\'m{{h}o)p${e]nob(ody[finds>-_$#thisone}}\';',  # Single-quotes
            'fooprivate_key\'m{{h}o)p${e]nob(ody[finds>-_$#thisone}}\';',  # Single-quotes
        ],
    },
}

FOLLOWED_BY_EQUAL_COMPARISON_SIGNS_QUOTES_REQUIRED_REGEX = {
    'negatives': {
        'quotes_required': [
            'my_password == ""',  # Nothing in the quotes
            "my_password == ''",  # Nothing in the quotes
            'my_password == "fakesecret"',  # 'fake' in the secret
        ],
    },
    'positives': {
        'quotes_required': [
            'some_dict["secret"] == "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            'the_password== "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"\n',
            'the_password==\'m{{h}o)p${e]nob(ody[finds>-_$#thisone}}\'\n',
            'some_dict["secret"] != "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            'the_password!= "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"\n',
            'the_password===\'m{{h}o)p${e]nob(ody[finds>-_$#thisone}}\'\n',
            'the_password!==\'m{{h}o)p${e]nob(ody[finds>-_$#thisone}}\'\n',
        ],
    },
}

PRECEDED_BY_EQUAL_COMPARISON_SIGNS_QUOTES_REQUIRED_REGEX = {
    'negatives': {
        'quotes_required': [
            '"" == my_password',  # Nothing in the quotes
            "'' == my_password",  # Nothing in the quotes
            '"fakesecret" == my_password',  # 'fake' in the secret
        ],
    },
    'positives': {
        'quotes_required': [
            '"m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" == password\n',
            '\'m{{h}o)p${e]nob(ody[finds>-_$#thisone}}\' == password\n',
            '"m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" != password\n',
            '\'m{{h}o)p${e]nob(ody[finds>-_$#thisone}}\' === password\n',
            '\'m{{h}o)p${e]nob(ody[finds>-_$#thisone}}\'!== password\n',
        ],
    },
}

QUOTES_REQUIRED_FILE_EXTENSIONS = (
    '.cls',
    '.java',
    '.js',
    '.py',
    '.swift',
)

STANDARD_POSITIVES = []
STANDARD_POSITIVES.extend(
    FOLLOWED_BY_COLON_RE.get('positives').get('quotes_required')
    + FOLLOWED_BY_COLON_RE.get('positives').get('quotes_not_required')
    + FOLLOWED_BY_EQUAL_SIGNS_RE.get('positives').get('quotes_required')
    + FOLLOWED_BY_EQUAL_SIGNS_RE.get('positives').get('quotes_not_required')
    + FOLLOWED_BY_QUOTES_AND_SEMICOLON_RE.get('positives').get('quotes_required')
    + FOLLOWED_BY_EQUAL_COMPARISON_SIGNS_QUOTES_REQUIRED_REGEX.get('positives').get('quotes_required')   # noqa: E501
    + PRECEDED_BY_EQUAL_COMPARISON_SIGNS_QUOTES_REQUIRED_REGEX.get('positives').get('quotes_required'),  # noqa: E501
)


class TestKeywordDetector:

    @pytest.mark.parametrize(
        'file_content',
        STANDARD_POSITIVES,
    )
    def test_analyze_standard_positives(self, file_content):
        secrets = list(KeywordDetector().analyze_string(file_content))

        assert len(secrets) == 1
        assert secrets[0] == 'm{{h}o)p${e]nob(ody[finds>-_$#thisone}}'

    @pytest.mark.parametrize(
        'file_content, file_extension',
        (
            (positive, file_extension)
            for positive in (
                FOLLOWED_BY_COLON_RE.get('positives').get('quotes_required')
                + FOLLOWED_BY_EQUAL_SIGNS_RE.get('positives').get('quotes_required')
                + FOLLOWED_BY_QUOTES_AND_SEMICOLON_RE.get('positives').get('quotes_required')
            ) for file_extension in QUOTES_REQUIRED_FILE_EXTENSIONS
        ),
    )
    def test_analyze_quotes_required_positives(self, file_content, file_extension):
        secrets = KeywordDetector().analyze_line(
            filename='mock_filename{}'.format(file_extension),
            line=file_content,
        )

        assert len(secrets) == 1
        assert list(secrets)[0].secret_value == 'm{{h}o)p${e]nob(ody[finds>-_$#thisone}}'

    @pytest.mark.parametrize(
        'file_content',
        FOLLOWED_BY_EQUAL_SIGNS_RE.get('positives').get('quotes_required')
        + FOLLOWED_BY_EQUAL_SIGNS_RE.get('positives').get('quotes_not_required')
        + FOLLOWED_BY_QUOTES_AND_SEMICOLON_RE.get('positives').get('quotes_required')
        + FOLLOWED_BY_COLON_EQUAL_SIGNS_RE.get('positives').get('quotes_required')
        + FOLLOWED_BY_COLON_EQUAL_SIGNS_RE.get('positives').get('quotes_not_required'),
    )
    def test_analyze_go_positives(self, file_content):
        secrets = KeywordDetector().analyze_line(filename='mock_filename.go', line=file_content)

        assert len(secrets) == 1
        assert list(secrets)[0].secret_value == 'm{{h}o)p${e]nob(ody[finds>-_$#thisone}}'

    @pytest.mark.parametrize(
        'file_content',
        FOLLOWED_BY_EQUAL_SIGNS_OPTIONAL_BRACKETS_OPTIONAL_AT_SIGN_QUOTES_REQUIRED_REGEX.get(
            'positives',
        ).get('quotes_required'),
    )
    def test_analyze_objective_c_positives(self, file_content):
        secrets = KeywordDetector().analyze_line(filename='mock_filename.m', line=file_content)

        assert len(secrets) == 1
        assert list(secrets)[0].secret_value == 'm{{h}o)p${e]nob(ody[finds>-_$#thisone}}'

    @staticmethod
    @pytest.mark.parametrize(
        'line',
        (
            'apiKey: this.apiKey,',
            "apiKey: fs.readFileSync('foo',",
        ),
    )
    def test_analyze_javascript_negatives(line):
        with transient_settings({
            'plugins_used': [{
                'name': 'KeywordDetector',
            }],
        }):
            assert list(scan_line(line))

            with tempfile.NamedTemporaryFile(suffix='.js') as f:
                f.write(line.encode('utf-8'))
                f.seek(0)

                assert not list(scan_file(f.name))

    @staticmethod
    def test_ignore_case():
        with transient_settings({
            'plugins_used': [{
                'name': 'KeywordDetector',
            }],
        }):
            assert list(scan_line('os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"'))
