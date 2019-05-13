from __future__ import absolute_import
from __future__ import unicode_literals

import pytest

from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.plugins.keyword import KeywordDetector
from testing.mocks import mock_file_object


QUOTES_REQUIRED_FILE_EXTENSIONS = (
    '.cls',
    '.java',
    '.py',
)
FOLLOWED_BY_COLON_RE = {
    "negatives": {
        "quotes_required": [
            'theapikey: ""',  # Nothing in the quotes
            'theapikey: "somefakekey"',  # 'fake' in the secret
            'token: "somefaketoken"',  # 'fake' in the secret
        ],
        "quotes_not_required": [
            'theapikeyforfoo:hopenobodyfindsthisone',  # Characters between apikey and :
            'password: ${link}',  # Has a ${ followed by a }
        ],
    },
    "positives": {
        "quotes_required": [
            "'theapikey': '{{h}o)p${e]nob(ody[finds>-_$#thisone}}'",
            '"theapikey": "{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            'apikey: "{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            "apikey:  '{{h}o)p${e]nob(ody[finds>-_$#thisone}}'",
            "token:  '{{h}o)p${e]nob(ody[finds>-_$#thisone}}'",
        ],
        "quotes_not_required": [
            'apikey: {{h}o)p${e]nob(ody[finds>-_$#thisone}}',
            'apikey:{{h}o)p${e]nob(ody[finds>-_$#thisone}}',
            'theapikey:{{h}o)p${e]nob(ody[finds>-_$#thisone}}',
            'token:{{h}o)p${e]nob(ody[finds>-_$#thisone}}',
        ],
    },
}
FOLLOWED_BY_EQUAL_SIGNS_RE = {
    "negatives": {
        "quotes_required": [
            'some_key = "real_secret"',  # We cannot make 'key' a Keyword, too noisy
            'my_password = ""',  # Nothing in the quotes
            "my_password = ''",  # Nothing in the quotes
            'my_password = "fakesecret"',  # 'fake' in the secret
            'open(self, password = ""):',  # secrets is ""):
            'open(self, password = ""):',  # secrets is ""):
        ],
        "quotes_not_required": [
            'my_password = foo(hey)you',  # Has a ( followed by a )
            "my_password = request.json_body['hey']",  # Has a [ followed by a ]
            'my_password = True',  # 'True' is a known false-positive
            'login(username=username, password=password)',  # secret is password)
        ],
    },
    "positives": {
        "quotes_required": [
            'some_dict["secret"] = "{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            'the_password= "{{h}o)p${e]nob(ody[finds>-_$#thisone}}"\n',
            'the_password=\'{{h}o)p${e]nob(ody[finds>-_$#thisone}}\'\n',
            'apitoken=\'{{h}o)p${e]nob(ody[finds>-_$#thisone}}\'\n',
        ],
        "quotes_not_required": [
            "some_dict['secret'] = {{h}o)p${e]nob(ody[finds>-_$#thisone}}",
            'my_password={{h}o)p${e]nob(ody[finds>-_$#thisone}}',
            'my_password= {{h}o)p${e]nob(ody[finds>-_$#thisone}}',
            'my_password ={{h}o)p${e]nob(ody[finds>-_$#thisone}}',
            'my_password = {{h}o)p${e]nob(ody[finds>-_$#thisone}}',
            'my_password ={{h}o)p${e]nob(ody[finds>-_$#thisone}}',
            'the_password={{h}o)p${e]nob(ody[finds>-_$#thisone}}\n',
            'my_token={{h}o)p${e]nob(ody[finds>-_$#thisone}}\n',
        ],
    },
}
FOLLOWED_BY_QUOTES_AND_SEMICOLON_RE = {
    "negatives": {
        "quotes_required": [
            'private_key "";',  # Nothing in the quotes
            'private_key \'"no spaces\';',  # Has whitespace in the secret
            'private_key "fake";',  # 'fake' in the secret
            'private_key "hopenobodyfindsthisone\';',  # Double-quote does not match single-quote
            'private_key \'hopenobodyfindsthisone";',  # Single-quote does not match double-quote
        ],
    },
    "positives": {
        "quotes_required": [
            'apikey "{{h}o)p${e]nob(ody[finds>-_$#thisone}}";',  # Double-quotes
            'fooapikeyfoo "{{h}o)p${e]nob(ody[finds>-_$#thisone}}";',  # Double-quotes
            'fooapikeyfoo"{{h}o)p${e]nob(ody[finds>-_$#thisone}}";',  # Double-quotes
            'private_key \'{{h}o)p${e]nob(ody[finds>-_$#thisone}}\';',  # Single-quotes
            'fooprivate_keyfoo\'{{h}o)p${e]nob(ody[finds>-_$#thisone}}\';',  # Single-quotes
            'fooprivate_key\'{{h}o)p${e]nob(ody[finds>-_$#thisone}}\';',  # Single-quotes
        ],
    },
}
FOLLOWED_BY_COLON_EQUAL_SIGNS_RE = {
    "negatives": {
        "quotes_required": [
            'theapikey := ""',  # Nothing in the quotes
            'theapikey := "somefakekey"',  # 'fake' in the secret
            'token := "somefakekey"',  # 'fake' in the secret
        ],
        "quotes_not_required": [
            'theapikeyforfoo := hopenobodyfindsthisone',  # Characters between apikey and :=
        ],
    },
    "positives": {
        "quotes_required": [
            'apikey := "{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            'apikey :="{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            'apikey  :=   "{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            "apikey := '{{h}o)p${e]nob(ody[finds>-_$#thisone}}'",
            "apikey :='{{h}o)p${e]nob(ody[finds>-_$#thisone}}'",
            'apikey:= "{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            'apikey:="{{h}o)p${e]nob(ody[finds>-_$#thisone}}"',
            "apikey:= '{{h}o)p${e]nob(ody[finds>-_$#thisone}}'",
            "apikey:='{{h}o)p${e]nob(ody[finds>-_$#thisone}}'",
            "apikey:=  '{{h}o)p${e]nob(ody[finds>-_$#thisone}}'",
            "token:=  '{{h}o)p${e]nob(ody[finds>-_$#thisone}}'",
        ],
        "quotes_not_required": [
            "apikey := {{h}o)p${e]nob(ody[finds>-_$#thisone}}",
            "apikey :={{h}o)p${e]nob(ody[finds>-_$#thisone}}",
            "apikey:= {{h}o)p${e]nob(ody[finds>-_$#thisone}}",
            "apikey:={{h}o)p${e]nob(ody[finds>-_$#thisone}}",
            "thetoken:={{h}o)p${e]nob(ody[finds>-_$#thisone}}",
        ],
    },
}

STANDARD_NEGATIVES = []
STANDARD_POSITIVES = []

STANDARD_NEGATIVES.extend(
    FOLLOWED_BY_COLON_RE.get("negatives").get("quotes_required")
    + FOLLOWED_BY_COLON_RE.get("negatives").get("quotes_not_required")
    + FOLLOWED_BY_EQUAL_SIGNS_RE.get("negatives").get("quotes_required")
    + FOLLOWED_BY_EQUAL_SIGNS_RE.get("negatives").get("quotes_not_required")
    + FOLLOWED_BY_QUOTES_AND_SEMICOLON_RE.get("negatives").get("quotes_required")
    + FOLLOWED_BY_COLON_EQUAL_SIGNS_RE.get("negatives").get("quotes_required")
    + FOLLOWED_BY_COLON_EQUAL_SIGNS_RE.get("negatives").get("quotes_not_required"),
)
STANDARD_POSITIVES.extend(
    FOLLOWED_BY_COLON_RE.get("positives").get("quotes_required")
    + FOLLOWED_BY_COLON_RE.get("positives").get("quotes_not_required")
    + FOLLOWED_BY_EQUAL_SIGNS_RE.get("positives").get("quotes_required")
    + FOLLOWED_BY_EQUAL_SIGNS_RE.get("positives").get("quotes_not_required")
    + FOLLOWED_BY_QUOTES_AND_SEMICOLON_RE.get("positives").get("quotes_required"),
)


class TestKeywordDetector(object):

    @pytest.mark.parametrize(
        'file_content',
        STANDARD_POSITIVES,
    )
    def test_analyze_standard_positives(self, file_content):
        logic = KeywordDetector()

        f = mock_file_object(file_content)
        output = logic.analyze(f, 'mock_filename')
        assert len(output) == 1
        for potential_secret in output:
            assert 'mock_filename' == potential_secret.filename
            assert (
                potential_secret.secret_hash
                == PotentialSecret.hash_secret('{{h}o)p${e]nob(ody[finds>-_$#thisone}}')
            )

    @pytest.mark.parametrize(
        'file_content',
        STANDARD_POSITIVES,
    )
    def test_analyze_with_line_exclude(self, file_content):
        logic = KeywordDetector(keyword_exclude='thisone')

        f = mock_file_object(file_content)
        output = logic.analyze(f, 'mock_filename.foo')
        assert len(output) == 0

    @pytest.mark.parametrize(
        'file_content, file_extension',
        (
            (positive, file_extension)
            for positive in (
                FOLLOWED_BY_COLON_RE.get("positives").get("quotes_required")
                + FOLLOWED_BY_EQUAL_SIGNS_RE.get("positives").get("quotes_required")
                + FOLLOWED_BY_QUOTES_AND_SEMICOLON_RE.get("positives").get("quotes_required")
            ) for file_extension in QUOTES_REQUIRED_FILE_EXTENSIONS
        ),
    )
    def test_analyze_quotes_required_positives(self, file_content, file_extension):
        logic = KeywordDetector()

        f = mock_file_object(file_content)
        mock_filename = 'mock_filename{}'.format(file_extension)
        output = logic.analyze(f, mock_filename)
        assert len(output) == 1
        for potential_secret in output:
            assert mock_filename == potential_secret.filename
            assert (
                potential_secret.secret_hash
                == PotentialSecret.hash_secret('{{h}o)p${e]nob(ody[finds>-_$#thisone}}')
            )

    @pytest.mark.parametrize(
        'file_content',
        FOLLOWED_BY_EQUAL_SIGNS_RE.get("positives").get("quotes_required")
        + FOLLOWED_BY_EQUAL_SIGNS_RE.get("positives").get("quotes_not_required")
        + FOLLOWED_BY_QUOTES_AND_SEMICOLON_RE.get("positives").get("quotes_required")
        + FOLLOWED_BY_COLON_EQUAL_SIGNS_RE.get("positives").get("quotes_required")
        + FOLLOWED_BY_COLON_EQUAL_SIGNS_RE.get("positives").get("quotes_not_required"),
    )
    def test_analyze_go_positives(self, file_content):
        logic = KeywordDetector()

        f = mock_file_object(file_content)
        output = logic.analyze(f, 'mock_filename.go')
        assert len(output) == 1
        for potential_secret in output:
            assert 'mock_filename.go' == potential_secret.filename
            assert (
                potential_secret.secret_hash ==
                PotentialSecret.hash_secret('{{h}o)p${e]nob(ody[finds>-_$#thisone}}')
            )

    @pytest.mark.parametrize(
        'file_content',
        STANDARD_NEGATIVES,
    )
    def test_analyze_standard_negatives(self, file_content):
        logic = KeywordDetector()

        f = mock_file_object(file_content)
        output = logic.analyze(f, 'mock_filename.foo')
        assert len(output) == 0

    @pytest.mark.parametrize(
        'file_content',
        STANDARD_NEGATIVES + [
            # FOLLOWED_BY_COLON_RE
            'apiKey: this.apiKey,',
            "apiKey: fs.readFileSync('foo',",
        ],
    )
    def test_analyze_javascript_negatives(self, file_content):
        logic = KeywordDetector()

        f = mock_file_object(file_content)
        output = logic.analyze(f, 'mock_filename.js')
        assert len(output) == 0

    @pytest.mark.parametrize(
        'file_content',
        STANDARD_NEGATIVES + [
            # FOLLOWED_BY_EQUAL_SIGNS_RE
            '$password = $input;',
        ],
    )
    def test_analyze_php_negatives(self, file_content):
        logic = KeywordDetector()

        f = mock_file_object(file_content)
        output = logic.analyze(f, 'mock_filename.php')
        assert len(output) == 0

    @pytest.mark.parametrize(
        'file_content, file_extension',
        (
            (negative, file_extension)
            for negative in (
                STANDARD_NEGATIVES + [
                    # FOLLOWED_BY_COLON_QUOTES_REQUIRED_RE
                    'apikey: hope]nobody[finds>-_$#thisone',
                    'apikey:hope]nobody[finds>-_$#thisone',
                    'theapikey:hope]nobody[finds>-_$#thisone',
                    # FOLLOWED_BY_EQUAL_SIGNS_QUOTES_REQUIRED_RE
                    "some_dict['secret'] = hope]nobody[finds>-_$#thisone",
                    'my_password=hope]nobody[finds>-_$#thisone',
                    'my_password= hope]nobody[finds>-_$#thisone',
                    'my_password =hope]nobody[finds>-_$#thisone',
                    'my_password = hope]nobody[finds>-_$#thisone',
                    'my_password =hope]nobody[finds>-_$#thisone',
                    'the_password=hope]nobody[finds>-_$#thisone\n',
                ]
            ) for file_extension in QUOTES_REQUIRED_FILE_EXTENSIONS
        ),
    )
    def test_analyze_quotes_required_negatives(self, file_content, file_extension):
        logic = KeywordDetector()

        f = mock_file_object(file_content)
        output = logic.analyze(
            f,
            'mock_filename{}'.format(file_extension),
        )
        assert len(output) == 0

    @pytest.mark.parametrize(
        'file_content, file_extension',
        (
            (yaml_negative, file_extension)
            for yaml_negative in STANDARD_POSITIVES
            for file_extension in (
                '.yaml',
                '.yml',
            )
        ),
    )
    def test_analyze_yaml_negatives(self, file_content, file_extension):
        logic = KeywordDetector()

        f = mock_file_object(file_content)
        output = logic.analyze(
            f,
            'mock_filename{}'.format(file_extension),
        )
        assert len(output) == 0
