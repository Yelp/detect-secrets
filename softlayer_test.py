from __future__ import absolute_import

import pytest

from detect_secrets.plugins.softlayer import SoftLayerDetector


class TestSoftLayerDetector(object):

    sl_token = 'abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234'

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('--softlayer-api-key "{sl_token}"'.format(sl_token=sl_token), True,),
            ('--softlayer-api-key="{sl_token}"'.format(sl_token=sl_token), True,),
            ('--softlayer-api-key {sl_token}'.format(sl_token=sl_token), True,),
            ('--softlayer-api-key={sl_token}'.format(sl_token=sl_token), True,),
            ('http://api.softlayer.com/soap/v3/{sl_token}'.format(sl_token=sl_token), True,),
            ('http://api.softlayer.com/soap/v3.1/{sl_token}'.format(sl_token=sl_token), True,),
            ('softlayer_api_key: {sl_token}'.format(sl_token=sl_token), True,),
            ('softlayer-key : {sl_token}'.format(sl_token=sl_token), True,),
            ('SOFTLAYER-API-KEY : "{sl_token}"'.format(sl_token=sl_token), True,),
            ('"softlayer_api_key" : "{sl_token}"'.format(sl_token=sl_token), True,),
            ('softlayer-api-key: "{sl_token}"'.format(sl_token=sl_token), True,),
            ('"softlayer_api_key": "{sl_token}"'.format(sl_token=sl_token), True,),
            ('SOFTLAYER_API_KEY:"{sl_token}"'.format(sl_token=sl_token), True,),
            ('softlayer-key:{sl_token}'.format(sl_token=sl_token), True,),
            ('softlayer_key:"{sl_token}"'.format(sl_token=sl_token), True,),
            ('"softlayer_api_key":"{sl_token}"'.format(sl_token=sl_token), True,),
            ('softlayerapikey= {sl_token}'.format(sl_token=sl_token), True,),
            ('softlayer_api_key= "{sl_token}"'.format(sl_token=sl_token), True,),
            ('SOFTLAYERAPIKEY={sl_token}'.format(sl_token=sl_token), True,),
            ('softlayer_api_key="{sl_token}"'.format(sl_token=sl_token), True,),
            ('sl_api_key: {sl_token}'.format(sl_token=sl_token), True,),
            ('SLAPIKEY : {sl_token}'.format(sl_token=sl_token), True,),
            ('sl_apikey : "{sl_token}"'.format(sl_token=sl_token), True,),
            ('"sl_api_key" : "{sl_token}"'.format(sl_token=sl_token), True,),
            ('sl-key: "{sl_token}"'.format(sl_token=sl_token), True,),
            ('"sl_api_key": "{sl_token}"'.format(sl_token=sl_token), True,),
            ('sl_api_key:"{sl_token}"'.format(sl_token=sl_token), True,),
            ('sl_api_key:{sl_token}'.format(sl_token=sl_token), True,),
            ('sl-api-key:"{sl_token}"'.format(sl_token=sl_token), True,),
            ('"sl_api_key":"{sl_token}"'.format(sl_token=sl_token), True,),
            ('sl_key= {sl_token}'.format(sl_token=sl_token), True,),
            ('sl_api_key= "{sl_token}"'.format(sl_token=sl_token), True,),
            ('sl-api-key={sl_token}'.format(sl_token=sl_token), True,),
            ('slapi_key="{sl_token}"'.format(sl_token=sl_token), True,),
            ('slapikey:= {sl_token}'.format(sl_token=sl_token), True,),
            ('softlayer_api_key := {sl_token}'.format(sl_token=sl_token), True,),
            ('sl_api_key := "{sl_token}"'.format(sl_token=sl_token), True,),
            ('"softlayer_key" := "{sl_token}"'.format(sl_token=sl_token), True,),
            ('sl_api_key: "{sl_token}"'.format(sl_token=sl_token), True,),
            ('"softlayer_api_key":= "{sl_token}"'.format(sl_token=sl_token), True,),
            ('sl-api-key:="{sl_token}"'.format(sl_token=sl_token), True,),
            ('softlayer_api_key:={sl_token}'.format(sl_token=sl_token), True,),
            ('slapikey:"{sl_token}"'.format(sl_token=sl_token), True,),
            ('"softlayer_api_key":="{sl_token}"'.format(sl_token=sl_token), True,),
            ('sl-api-key:= {sl_token}'.format(sl_token=sl_token), True,),
            ('softlayer_key:= "{sl_token}"'.format(sl_token=sl_token), True,),
            ('sl_api_key={sl_token}'.format(sl_token=sl_token), True),
            ('softlayer_api_key:="{sl_token}"'.format(sl_token=sl_token), True),
            ('softlayer_api_key="%s" % SL_API_KEY_ENV', False),
            ('sl_api_key: "%s" % <softlayer_api_key>', False),
            ('SOFTLAYER_APIKEY: "insert_key_here"', False),
            ('sl-apikey: "insert_key_here"', False),
            ('softlayer-key:=afakekey', False),
            ('fake-softlayer-key= "not_long_enough"', False),
        ],
    )
    def test_analyze_string(self, payload, should_flag):
        logic = SoftLayerDetector()

        output = logic.analyze_string(payload, 1, 'mock_filename')
        assert len(output) == (1 if should_flag else 0)
