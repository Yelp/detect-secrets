from __future__ import absolute_import

import textwrap

import pytest
import responses
from mock import patch

from detect_secrets.core.constants import VerifiedResult
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.plugins.ibm_cos_hmac import find_access_key_id
from detect_secrets.plugins.ibm_cos_hmac import IBMCosHmacDetector
from detect_secrets.plugins.ibm_cos_hmac import verify_ibm_cos_hmac_credentials


ACCESS_KEY_ID = '1234567890abcdef1234567890abcdef'
SECRET_ACCESS_KEY = '1234567890abcdef1234567890abcdef1234567890abcdef'


class TestIBMCosHmacDetector(object):

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('"secret_access_key": "1234567890abcdef1234567890abcdef1234567890abcdef"', True),
            ('secret_access_key=1234567890abcdef1234567890abcdef1234567890abcdef', True),
            ('secret_access_key="1234567890abcdef1234567890abcdef1234567890abcdef"', True),
            ('secret_access_key=\'1234567890abcdef1234567890abcdef1234567890abcdef\'', True),
            ('secret_access_key = "1234567890abcdef1234567890abcdef1234567890abcdef"', True),
            (
                'COS_HMAC_SECRET_ACCESS_KEY = "1234567890abcdef1234567890abcdef1234567890abcdef"',
                True,
            ),
            (
                'ibm_cos_SECRET_ACCESS_KEY = "1234567890abcdef1234567890abcdef1234567890abcdef"',
                True,
            ),
            (
                'ibm_cos_secret_access_key = "1234567890abcdef1234567890abcdef1234567890abcdef"',
                True,
            ),
            ('ibm_cos_secret_key = "1234567890abcdef1234567890abcdef1234567890abcdef"', True),
            ('cos_secret_key = "1234567890abcdef1234567890abcdef1234567890abcdef"', True),
            ('ibm-cos_secret_key = "1234567890abcdef1234567890abcdef1234567890abcdef"', True),
            ('cos-hmac_secret_key = "1234567890abcdef1234567890abcdef1234567890abcdef"', True),
            ('coshmac_secret_key = "1234567890abcdef1234567890abcdef1234567890abcdef"', True),
            ('ibmcoshmac_secret_key = "1234567890abcdef1234567890abcdef1234567890abcdef"', True),
            ('ibmcos_secret_key = "1234567890abcdef1234567890abcdef1234567890abcdef"', True),
            ('not_secret = notapassword', False),
            ('someotherpassword = "doesnt start right"', False),
        ],
    )
    def test_analyze_string(self, payload, should_flag):
        logic = IBMCosHmacDetector()

        output = logic.analyze_string(payload, 1, 'mock_filename')
        assert len(output) == int(should_flag)

    @patch('detect_secrets.plugins.ibm_cos_hmac.verify_ibm_cos_hmac_credentials')
    def test_verify_invalid_secret(self, mock_hmac_verify):
        mock_hmac_verify.return_value = False

        potential_secret = PotentialSecret('test', 'test filename', SECRET_ACCESS_KEY)
        assert IBMCosHmacDetector().verify(
            SECRET_ACCESS_KEY,
            '''access_key_id={}'''.format(ACCESS_KEY_ID),
            potential_secret,
        ) == VerifiedResult.VERIFIED_FALSE

        mock_hmac_verify.assert_called_with(ACCESS_KEY_ID, SECRET_ACCESS_KEY)

    @patch('detect_secrets.plugins.ibm_cos_hmac.verify_ibm_cos_hmac_credentials')
    def test_verify_valid_secret(self, mock_hmac_verify):
        mock_hmac_verify.return_value = True

        potential_secret = PotentialSecret('test', 'test filename', SECRET_ACCESS_KEY)
        assert IBMCosHmacDetector().verify(
            SECRET_ACCESS_KEY,
            '''access_key_id={}'''.format(ACCESS_KEY_ID),
            potential_secret,
        ) == VerifiedResult.VERIFIED_TRUE

        mock_hmac_verify.assert_called_with(ACCESS_KEY_ID, SECRET_ACCESS_KEY)

    @patch('detect_secrets.plugins.ibm_cos_hmac.verify_ibm_cos_hmac_credentials')
    def test_verify_unverified_secret(self, mock_hmac_verify):
        mock_hmac_verify.side_effect = Exception('oops')

        potential_secret = PotentialSecret('test', 'test filename', SECRET_ACCESS_KEY)
        assert IBMCosHmacDetector().verify(
            SECRET_ACCESS_KEY,
            '''access_key_id={}'''.format(ACCESS_KEY_ID),
            potential_secret,
        ) == VerifiedResult.UNVERIFIED

        mock_hmac_verify.assert_called_with(ACCESS_KEY_ID, SECRET_ACCESS_KEY)

    @patch('detect_secrets.plugins.ibm_cos_hmac.verify_ibm_cos_hmac_credentials')
    def test_verify_unverified_secret_no_match(self, mock_hmac_verify):
        mock_hmac_verify.side_effect = Exception('oops')

        potential_secret = PotentialSecret('test', 'test filename', SECRET_ACCESS_KEY)
        assert IBMCosHmacDetector().verify(
            SECRET_ACCESS_KEY,
            '''something={}'''.format(ACCESS_KEY_ID),
            potential_secret,
        ) == VerifiedResult.UNVERIFIED

        mock_hmac_verify.assert_not_called()

    @pytest.mark.parametrize(
        'content, expected_output',
        (
            (
                textwrap.dedent("""
                    access_key_id = {}
                """)[1:-1].format(
                    ACCESS_KEY_ID,
                ),
                [ACCESS_KEY_ID],
            ),
            (
                'access_key_id = {}'.format(ACCESS_KEY_ID),
                [ACCESS_KEY_ID],
            ),
            (
                'access-key-id := {}'.format(ACCESS_KEY_ID),
                [ACCESS_KEY_ID],
            ),
            (
                "\"access_id\":\"{}\"".format(ACCESS_KEY_ID),
                [ACCESS_KEY_ID],
            ),
            (
                "key_id =  \"{}\"".format(ACCESS_KEY_ID),
                [ACCESS_KEY_ID],
            ),
            (
                "key-id = '{}'".format(ACCESS_KEY_ID),
                [ACCESS_KEY_ID],
            ),
            (
                "access_key = '{}'".format(ACCESS_KEY_ID),
                [ACCESS_KEY_ID],
            ),
            (
                "[\"access_key_id\"] = '{}'".format(ACCESS_KEY_ID),
                [ACCESS_KEY_ID],
            ),
            (
                'id = {}'.format(ACCESS_KEY_ID),
                [],
            ),
        ),
    )
    def test_find_access_key_id(self, content, expected_output):
        assert find_access_key_id(content) == expected_output


@pytest.mark.parametrize(
    'status_code, validation_result',
    [
        (200, True),
        (403, False),
    ],
)
@responses.activate
def test_verify_ibm_cos_hmac_credentials(status_code, validation_result):
    host = 'fake.s3.us.cloud-object-storage.appdomain.cloud'
    responses.add(
        responses.GET, 'https://{}//'.format(host),
        json={'some': 'thing'}, status=status_code,
    )

    assert verify_ibm_cos_hmac_credentials(
        ACCESS_KEY_ID, SECRET_ACCESS_KEY, host,
    ) is validation_result
    assert len(responses.calls) == 1
    headers = responses.calls[0].request.headers
    assert headers['Authorization'].startswith('AWS4-HMAC-SHA256')
    assert headers['x-amz-date'] is not None
