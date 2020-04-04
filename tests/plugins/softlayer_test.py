import textwrap

import pytest
import responses

from detect_secrets.core.constants import VerifiedResult
from detect_secrets.plugins.softlayer import find_username
from detect_secrets.plugins.softlayer import SoftlayerDetector

SL_USERNAME = 'test@testy.test'
SL_TOKEN = 'abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234'


class TestSoftlayerDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('--softlayer-api-key "{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('--softlayer-api-key="{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('--softlayer-api-key {sl_token}'.format(sl_token=SL_TOKEN), True),
            ('--softlayer-api-key={sl_token}'.format(sl_token=SL_TOKEN), True),
            ('http://api.softlayer.com/soap/v3/{sl_token}'.format(sl_token=SL_TOKEN), True),
            ('http://api.softlayer.com/soap/v3.1/{sl_token}'.format(sl_token=SL_TOKEN), True),
            ('softlayer_api_key: {sl_token}'.format(sl_token=SL_TOKEN), True),
            ('softlayer-key : {sl_token}'.format(sl_token=SL_TOKEN), True),
            ('SOFTLAYER-API-KEY : "{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('"softlayer_api_key" : "{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('softlayer-api-key: "{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('"softlayer_api_key": "{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('SOFTLAYER_API_KEY:"{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('softlayer-key:{sl_token}'.format(sl_token=SL_TOKEN), True),
            ('softlayer_key:"{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('"softlayer_api_key":"{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('softlayerapikey= {sl_token}'.format(sl_token=SL_TOKEN), True),
            ('softlayer_api_key= "{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('SOFTLAYERAPIKEY={sl_token}'.format(sl_token=SL_TOKEN), True),
            ('softlayer_api_key="{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('sl_api_key: {sl_token}'.format(sl_token=SL_TOKEN), True),
            ('SLAPIKEY : {sl_token}'.format(sl_token=SL_TOKEN), True),
            ('sl_apikey : "{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('"sl_api_key" : "{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('sl-key: "{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('"sl_api_key": "{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('sl_api_key:"{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('sl_api_key:{sl_token}'.format(sl_token=SL_TOKEN), True),
            ('sl-api-key:"{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('"sl_api_key":"{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('sl_key= {sl_token}'.format(sl_token=SL_TOKEN), True),
            ('sl_api_key= "{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('sl-api-key={sl_token}'.format(sl_token=SL_TOKEN), True),
            ('slapi_key="{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('slapikey:= {sl_token}'.format(sl_token=SL_TOKEN), True),
            ('softlayer_api_key := {sl_token}'.format(sl_token=SL_TOKEN), True),
            ('sl_api_key := "{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('"softlayer_key" := "{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('sl_api_key: "{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('"softlayer_api_key":= "{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('sl-api-key:="{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('softlayer_api_key:={sl_token}'.format(sl_token=SL_TOKEN), True),
            ('slapikey:"{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('"softlayer_api_key":="{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('sl-api-key:= {sl_token}'.format(sl_token=SL_TOKEN), True),
            ('softlayer_key:= "{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('sl_api_key={sl_token}'.format(sl_token=SL_TOKEN), True),
            ('softlayer_api_key:="{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('softlayer_password = "{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('sl_pass="{sl_token}"'.format(sl_token=SL_TOKEN), True),
            ('softlayer-pwd = {sl_token}'.format(sl_token=SL_TOKEN), True),
            ('softlayer_api_key="%s" % SL_API_KEY_ENV', False),
            ('sl_api_key: "%s" % <softlayer_api_key>', False),
            ('SOFTLAYER_APIKEY: "insert_key_here"', False),
            ('sl-apikey: "insert_key_here"', False),
            ('softlayer-key:=afakekey', False),
            ('fake-softlayer-key= "not_long_enough"', False),
        ],
    )
    def test_analyze_line(self, payload, should_flag):
        logic = SoftlayerDetector()

        output = logic.analyze_line(payload, 1, 'mock_filename')
        assert len(output) == (1 if should_flag else 0)

    @responses.activate
    def test_verify_invalid_secret(self):
        responses.add(
            responses.GET, 'https://api.softlayer.com/rest/v3/SoftLayer_Account.json',
            json={'error': 'Access denied. '}, status=401,
        )

        assert SoftlayerDetector().verify(
            SL_TOKEN,
            'softlayer_username={}'.format(SL_USERNAME),
        ) == VerifiedResult.VERIFIED_FALSE

    @responses.activate
    def test_verify_valid_secret(self):
        responses.add(
            responses.GET, 'https://api.softlayer.com/rest/v3/SoftLayer_Account.json',
            json={'id': 1}, status=200,
        )
        assert SoftlayerDetector().verify(
            SL_TOKEN,
            'softlayer_username={}'.format(SL_USERNAME),
        ) == VerifiedResult.VERIFIED_TRUE

    @responses.activate
    def test_verify_unverified_secret(self):
        assert SoftlayerDetector().verify(
            SL_TOKEN,
            'softlayer_username={}'.format(SL_USERNAME),
        ) == VerifiedResult.UNVERIFIED

    def test_verify_no_secret(self):
        assert SoftlayerDetector().verify(
            SL_TOKEN,
            'no_un={}'.format(SL_USERNAME),
        ) == VerifiedResult.UNVERIFIED

    @pytest.mark.parametrize(
        'content, expected_output',
        (
            (
                textwrap.dedent("""
                    --softlayer-username = {}
                """)[1:-1].format(
                    SL_USERNAME,
                ),
                [SL_USERNAME],
            ),

            # With quotes
            (
                textwrap.dedent("""
                    sl_user_id = "{}"
                """)[1:-1].format(
                    SL_USERNAME,
                ),
                [SL_USERNAME],
            ),

            # multiple candidates
            (
                textwrap.dedent("""
                    softlayer_id = '{}'
                    sl-user = '{}'
                    SOFTLAYER_USERID = '{}'
                    softlayer-uname: {}
                """)[1:-1].format(
                    SL_USERNAME,
                    'test2@testy.test',
                    'test3@testy.testy',
                    'notanemail',
                ),
                [
                    SL_USERNAME,
                    'test2@testy.test',
                    'test3@testy.testy',
                    'notanemail',
                ],
            ),
        ),
    )
    def test_find_username(self, content, expected_output):
        assert find_username(content) == expected_output
