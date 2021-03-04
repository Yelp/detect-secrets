import pytest
import responses

from detect_secrets.core.constants import VerifiedResult
from detect_secrets.plugins.ibm_cloud_iam import IbmCloudIamDetector


CLOUD_IAM_KEY = 'abcd1234abcd1234abcd1234ABCD1234ABCD1234--__'
CLOUD_IAM_KEY_BYTES = b'abcd1234abcd1234abcd1234ABCD1234ABCD1234--__'


class TestIbmCloudIamDetector(object):

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('ibm-cloud_api_key: {cloud_iam_key}'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('apikeyid: {cloud_iam_key}'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('ibm_cloud_iam-key : {cloud_iam_key}'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('IBM-API-KEY : "{cloud_iam_key}"'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('"iam_api_key" : "{cloud_iam_key}"'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('cloud-api-key: "{cloud_iam_key}"'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('"iam-password": "{cloud_iam_key}"'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('CLOUD_IAM_API_KEY:"{cloud_iam_key}"'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('ibm-cloud-key:{cloud_iam_key}'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('ibm_key:"{cloud_iam_key}"'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('auth:"{cloud_iam_key}"'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            (
                '"ibm_cloud_iam_api_key":"{cloud_iam_key}"'.format(
                    cloud_iam_key=CLOUD_IAM_KEY,
                ), True,
            ),
            ('ibm_cloud_iamapikey= {cloud_iam_key}'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('ibm_cloud_api_key= "{cloud_iam_key}"'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('IBMCLOUDIAMAPIKEY={cloud_iam_key}'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('cloud_iam_api_key="{cloud_iam_key}"'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('ibm_api_key := {cloud_iam_key}'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('"ibm-iam_key" := "{cloud_iam_key}"'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            (
                '"X-Require-Whisk-Auth" = "{cloud_iam_key}"'.format(
                    cloud_iam_key=CLOUD_IAM_KEY,
                ), True,
            ),
            (
                '"ibm_cloud_iam_api_key":= "{cloud_iam_key}"'.format(
                    cloud_iam_key=CLOUD_IAM_KEY,
                ), True,
            ),
            ('ibm-cloud_api_key:={cloud_iam_key}'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('"cloud_iam_api_key":="{cloud_iam_key}"'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('ibm_iam_key:= "{cloud_iam_key}"'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('ibm_api_key:="{cloud_iam_key}"'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('ibm_password = "{cloud_iam_key}"'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('test_apikey = "{cloud_iam_key}"'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('ibm-cloud-pwd = {cloud_iam_key}'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('ibm-cloud-creds = {cloud_iam_key}'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('CREDENTIALS = {cloud_iam_key}'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('apikey:{cloud_iam_key}'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('IAMAuthenticator("{cloud_iam_key}")'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('.set("apikey", "{cloud_iam_key}")'.format(cloud_iam_key=CLOUD_IAM_KEY), True),
            ('iam_api_key="%s" % IBM_IAM_API_KEY_ENV', False),
            ('CLOUD_APIKEY: "insert_key_here"', False),
            ('cloud-iam-key:=afakekey', False),
            ('fake-cloud-iam-key= "not_long_enough"', False),
        ],
    )
    def test_analyze_line(self, payload, should_flag):
        logic = IbmCloudIamDetector()

        output = logic.analyze_line(payload, 1, 'mock_filename')
        assert len(output) == (1 if should_flag else 0)

    @responses.activate
    def test_verify_invalid_secret(self):
        responses.add(
            responses.POST, 'https://iam.cloud.ibm.com/identity/introspect', status=200,
            json={'active': False}, headers={'content-type': 'application/json'},
        )

        assert IbmCloudIamDetector().verify(CLOUD_IAM_KEY) == VerifiedResult.VERIFIED_FALSE

    @responses.activate
    def test_verify_valid_secret(self):
        responses.add(
            responses.POST, 'https://iam.cloud.ibm.com/identity/introspect', status=200,
            json={'active': True}, headers={'content-type': 'application/json'},
        )

        assert IbmCloudIamDetector().verify(CLOUD_IAM_KEY) == VerifiedResult.VERIFIED_TRUE

    @responses.activate
    def test_verify_invalid_secret_bytes(self):
        responses.add(
            responses.POST, 'https://iam.cloud.ibm.com/identity/introspect', status=200,
            json={'active': False}, headers={'content-type': 'application/json'},
        )

        assert IbmCloudIamDetector().verify(CLOUD_IAM_KEY_BYTES) == VerifiedResult.VERIFIED_FALSE

    @responses.activate
    def test_verify_valid_secret_bytes(self):
        responses.add(
            responses.POST, 'https://iam.cloud.ibm.com/identity/introspect', status=200,
            json={'active': True}, headers={'content-type': 'application/json'},
        )

        assert IbmCloudIamDetector().verify(CLOUD_IAM_KEY_BYTES) == VerifiedResult.VERIFIED_TRUE

    @responses.activate
    def test_verify_bad_response(self):
        responses.add(
            responses.POST, 'https://iam.cloud.ibm.com/identity/introspect', status=404,
        )

        assert IbmCloudIamDetector().verify(CLOUD_IAM_KEY_BYTES) == VerifiedResult.UNVERIFIED

    @responses.activate
    def test_verify_invalid_payload(self):
        responses.add(
            responses.POST, 'https://iam.cloud.ibm.com/identity/introspect', status=200,
            json={'not-the-field': 'we expect'}, headers={'content-type': 'application/json'},
        )

        assert IbmCloudIamDetector().verify(CLOUD_IAM_KEY) == VerifiedResult.UNVERIFIED

    @responses.activate
    def test_verify_payload_not_json(self):
        responses.add(
            responses.POST, 'https://iam.cloud.ibm.com/identity/introspect', status=200,
            body='not json', headers={'content-type': 'not/json'},
        )

        with pytest.raises(Exception):
            IbmCloudIamDetector().verify(CLOUD_IAM_KEY)
