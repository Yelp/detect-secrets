import pytest

from detect_secrets.plugins.keyword_xml import KeywordXMLDetector


XML_KEYWORD_IN_TAG_RE = {
    'negatives': [
        '<the_password>somefakesecret</the_password>',  # 'fake' in the secret
    ],
    'positives': [
        '<the_password> m{{h}o)p${e]nob(ody[finds>-_$#thisone}} </the_password>',
        '<the_password> m{{h}o)p${e]nob(ody[finds>-_$#thisone}}</the_password>',
        '<the_password>m{{h}o)p${e]nob(ody[finds>-_$#thisone}} </the_password>',
        '<the_password>m{{h}o)p${e]nob(ody[finds>-_$#thisone}}</the_password>',
        '< the_password > m{{h}o)p${e]nob(ody[finds>-_$#thisone}} </the_password>',
        '<the_password > m{{h}o)p${e]nob(ody[finds>-_$#thisone}} </the_password>',
        '< the_password> m{{h}o)p${e]nob(ody[finds>-_$#thisone}} </the_password>',
        '<the_password_tag> m{{h}o)p${e]nob(ody[finds>-_$#thisone}} </the_password_tag>',
    ],
}
XML_KEYWORD_IN_NAME_PROP_RE = {
    'negatives': [
        '<sometag name="password" value="somefakesecret" />',  # 'fake' in the secret
        '<sometag name="password" value="" />',  # Nothing in the quotes
    ],
    'positives': [
        '< sometag name="the_password" value="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" />',
        '<sometag name="the_password" value="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" />',
        '<sometag name = "the_password" value="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" />',
        '<sometag name ="the_password" value="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" />',
        '<sometag name= "the_password" value="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" />',
        '<sometag name="the_password" value = "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" />',
        '<sometag name="the_password" value ="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" />',
        '<sometag name="the_password" value= "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" />',
        '<sometag name="the_password" value="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"/>',
        '< sometag value="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" name="the_password" />',
        '<sometag value="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" name="the_password" />',
        '<sometag value="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" name="the_password"/>',
        '<sometag value = "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" name="the_password"/>',
        '<sometag value ="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" name="the_password"/>',
        '<sometag value= "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" name="the_password"/>',
        '<sometag value="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" name = "the_password"/>',
        '<sometag value="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" name ="the_password"/>',
        '<sometag value="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" name= "the_password"/>',
        '<sometag value="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" name="the_password_attribute"/>',
        '<sometag value="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" name="the_password_attribute">something</sometag>',   # noqa: E501
        "<sometag value='m{{h}o)p${e]nob(ody[finds>-_$#thisone}}' name='the_password_attribute'/>",
    ],
}
XML_KEYWORD_VALUE_RE = {
    'negatives': [
        '<sometag name="the_password">somefakesecret</sometag>',  # 'fake' in the secret
    ],
    'positives': [
        '< sometag name="the_password" >m{{h}o)p${e]nob(ody[finds>-_$#thisone}}</sometag>',
        '< sometag name="the_password">m{{h}o)p${e]nob(ody[finds>-_$#thisone}}</sometag>',
        '<sometag name="the_password" >m{{h}o)p${e]nob(ody[finds>-_$#thisone}}</sometag>',
        '<sometag name = "the_password" >m{{h}o)p${e]nob(ody[finds>-_$#thisone}}</sometag>',
        '<sometag name= "the_password" >m{{h}o)p${e]nob(ody[finds>-_$#thisone}}</sometag>',
        '<sometag name ="the_password" >m{{h}o)p${e]nob(ody[finds>-_$#thisone}}</sometag>',
        '<sometag name="the_password">m{{h}o)p${e]nob(ody[finds>-_$#thisone}}</sometag>',
        '<sometag name="the_password_att">m{{h}o)p${e]nob(ody[finds>-_$#thisone}}</sometag>',
        "<sometag name='the_password_att'>m{{h}o)p${e]nob(ody[finds>-_$#thisone}}</sometag>",
    ],
}
XML_KEYWORD_VALUE_IN_PROP_RE = {
    'negatives': [
        '<the_password value="somefakesecret"/>',  # 'fake' in the secret
        '<the_password value=""/>',  # Nothing in the quotes
    ],
    'positives': [
        '<the_password value="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"/>',
        '<the_password value = "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"/>',
        '<the_password value= "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"/>',
        '<the_password value ="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"/>',
        '< the_password value="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"/>',
        '<the_password value="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" />',
        '<the_password value="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" />',
        '<the_password_tag value="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" />',
        '<the_password_tag value="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}">something</the_password_tag>',     # noqa: E501
        "<the_password_tag value='m{{h}o)p${e]nob(ody[finds>-_$#thisone}}' />",
    ],
}
FOLLOWED_BY_EQUAL_SIGNS_QUOTES_REQUIRED_RE = {
    'negatives': [
        '<sometag the_password="somefakesecret"/>',  # 'fake' in the secret
        '<sometag the_password=""/>',  # Nothing in the quotes
    ],
    'positives': [
        '<sometag the_password="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"/>',
        '<sometag the_password = "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"/>',
        '<sometag the_password ="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"/>',
        '<sometag the_password= "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"/>',
        '< sometag the_password="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"/>',
        '<sometag the_password="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" />',
        '<sometag the_password="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" />',
        '<sometag the_password_att="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}" />',
        '<sometag the_password="m{{h}o)p${e]nob(ody[finds>-_$#thisone}}">something</sometag>',
        "<sometag the_password='m{{h}o)p${e]nob(ody[finds>-_$#thisone}}' />",
    ],
}

XML_NEGATIVES = []
XML_POSITIVES = []

XML_NEGATIVES.extend(
    XML_KEYWORD_IN_TAG_RE.get('negatives')
    + XML_KEYWORD_IN_NAME_PROP_RE.get('negatives')
    + XML_KEYWORD_VALUE_RE.get('negatives')
    + XML_KEYWORD_VALUE_IN_PROP_RE.get('negatives')
    + FOLLOWED_BY_EQUAL_SIGNS_QUOTES_REQUIRED_RE.get('negatives'),
)
XML_POSITIVES.extend(
    XML_KEYWORD_IN_TAG_RE.get('positives')
    + XML_KEYWORD_IN_NAME_PROP_RE.get('positives')
    + XML_KEYWORD_VALUE_RE.get('positives')
    + XML_KEYWORD_VALUE_IN_PROP_RE.get('positives')
    + FOLLOWED_BY_EQUAL_SIGNS_QUOTES_REQUIRED_RE.get('positives'),
)


class TestKeywordDetector:

    @pytest.mark.parametrize(
        'file_content',
        XML_POSITIVES,
    )
    def test_analyze_xml_positives(self, file_content):
        secrets = list(KeywordXMLDetector().analyze_string(file_content))

        assert len(secrets) == 1
        assert secrets[0] == 'm{{h}o)p${e]nob(ody[finds>-_$#thisone}}'

    @pytest.mark.skip(
        reason='TODO: false positive heuristics need to be migrated over to filters/*',
    )
    @pytest.mark.parametrize(
        'file_content',
        XML_NEGATIVES,
    )
    def test_analyze_xml_negatives(self, file_content):
        assert not KeywordXMLDetector().analyze_line(
            filename='mock_filename.xml',

            # Make it start with `<`, (and end with `>`) so it hits our false-positive check
            line=file_content.replace('m{', '<').replace('}', '>'),
        )
