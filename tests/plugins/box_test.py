import pytest
from mock import patch

from detect_secrets.core.constants import VerifiedResult
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.plugins.box import BoxDetector
from detect_secrets.plugins.box import find_other_factor
from detect_secrets.plugins.box import get_box_user

BOX_CLIENT_ID = 'abcd1234abcd1234abcd1234abcd1234'
BOX_CLIENT_SECRET = 'abcd1234ABCD1234abcd1234ABCD1234'
BOX_PUBLIC_KEY_ID = 'abcd1234'
BOX_PRIVATE_KEY = '-----BEGIN ENCRYPTED PRIVATE KEY----- key -----END ENCRYPTED PRIVATE KEY-----\n'
BOX_PASSPHRASE = 'abcd1234abcd1234abcd1234abcd1234'
BOX_ENTERPRISE_ID = '1234'


class TestBoxDetector(object):

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('"clientSecret": "12345678abcdefgh12345678ABCDEFGH"', True),
            ('client_secret = 12345678abcdefgh12345678ABCDEFGH', True),
            ('CLIENT-SECRET=12345678abcdefgh12345678ABCDEFGH', True),
            ('"clientsecret":="12345678abcdefgh12345678ABCDEFGH"', True),
            ('"clientSecret": "12345678abcdefgh12345678ABCDEFG2many"', True),
            ('"clientSecret": "12345678abcdnotenough"', False),
        ],
    )
    def test_analyze_line(self, payload, should_flag):
        logic = BoxDetector()

        output = logic.analyze_line(payload, 1, 'mock_filename')
        assert len(output) == int(should_flag)

    @patch('detect_secrets.plugins.box.JWTAuth')
    @patch('detect_secrets.plugins.box.Client')
    def test_get_box_user(self, mock_box, mock_jwt):
        mock_box.return_value.user.return_value.get.return_value.name = 'Testy'

        assert get_box_user(
            BOX_CLIENT_ID, BOX_CLIENT_SECRET, BOX_ENTERPRISE_ID,
            BOX_PUBLIC_KEY_ID, BOX_PASSPHRASE, BOX_PRIVATE_KEY,
        ) == 'Testy'

    @patch('detect_secrets.plugins.box.JWTAuth')
    @patch('detect_secrets.plugins.box.Client')
    def test_get_box_user_invalid_creds(self, mock_box, mock_jwt):
        mock_box.side_effect = Exception('oops')

        assert get_box_user(
            BOX_CLIENT_ID, BOX_CLIENT_SECRET, BOX_ENTERPRISE_ID,
            BOX_PUBLIC_KEY_ID, BOX_PASSPHRASE, BOX_PRIVATE_KEY,
        ) is None

    @patch('detect_secrets.plugins.box.JWTAuth')
    @patch('detect_secrets.plugins.box.Client')
    def test_verify(self, mock_box, mock_jwt):
        mock_box.return_value.user.return_value.get.return_value.name = 'Testy'

        potential_secret = PotentialSecret('test box', 'test filename', BOX_CLIENT_SECRET)

        assert BoxDetector().verify(
            BOX_CLIENT_SECRET,
            '''{
                 "boxAppSettings": {
                   "clientID": "%s",
                   "clientSecret": "%s",
                   "appAuth": {
                     "publicKeyID": "%s",
                     "privateKey": "%s",
                     "passphrase": "%s"
                   }
                 },
                 "enterpriseID": "%s"
               }
            ''' % (
                BOX_CLIENT_ID, BOX_CLIENT_SECRET, BOX_PUBLIC_KEY_ID,
                BOX_PRIVATE_KEY, BOX_PASSPHRASE, BOX_ENTERPRISE_ID,
            ),
            potential_secret,
        ) == VerifiedResult.VERIFIED_TRUE

        mock_box.assert_called()
        assert potential_secret.other_factors['clientID'] == BOX_CLIENT_ID
        assert potential_secret.other_factors['publicKeyID'] == BOX_PUBLIC_KEY_ID
        assert potential_secret.other_factors['privateKey'] == BOX_PRIVATE_KEY
        assert potential_secret.other_factors['passphrase'] == BOX_PASSPHRASE
        assert potential_secret.other_factors['enterpriseID'] == BOX_ENTERPRISE_ID

    @patch('detect_secrets.plugins.box.JWTAuth')
    @patch('detect_secrets.plugins.box.Client')
    def test_verify_invalid(self, mock_box, mock_jwt):
        mock_box.side_effect = Exception('oops')

        potential_secret = PotentialSecret('test box', 'test filename', BOX_CLIENT_SECRET)

        assert BoxDetector().verify(
            BOX_CLIENT_SECRET,
            '''"clientID": "{}",
               "clientSecret": "{}",
               "publicKeyID": "{}",
               "privateKey": "{}",
               "passphrase": "{}",
               "enterpriseID": "{}"
            '''.format(
                BOX_CLIENT_ID, BOX_CLIENT_SECRET, BOX_PUBLIC_KEY_ID,
                BOX_PRIVATE_KEY, BOX_PASSPHRASE, BOX_ENTERPRISE_ID,
            ),
            potential_secret,
        ) == VerifiedResult.VERIFIED_FALSE

        mock_box.assert_called()

    @patch('detect_secrets.plugins.box.JWTAuth')
    @patch('detect_secrets.plugins.box.Client')
    def test_verify_unverified_missing_clientid(self, mock_box, mock_jwt):
        mock_box.side_effect = Exception('oops')

        potential_secret = PotentialSecret('test box', 'test filename', BOX_CLIENT_SECRET)

        assert BoxDetector().verify(
            BOX_CLIENT_SECRET,
            '''"clientSecret": "{}",
               "publicKeyID": "{}",
               "privateKey": "{}",
               "passphrase": "{}",
               "enterpriseID": "{}"
            '''.format(
                BOX_CLIENT_SECRET, BOX_PUBLIC_KEY_ID,
                BOX_PRIVATE_KEY, BOX_PASSPHRASE, BOX_ENTERPRISE_ID,
            ),
            potential_secret,
        ) == VerifiedResult.UNVERIFIED

    @patch('detect_secrets.plugins.box.JWTAuth')
    @patch('detect_secrets.plugins.box.Client')
    def test_verify_unverified_missing_publickeyid(self, mock_box, mock_jwt):
        mock_box.side_effect = Exception('oops')

        potential_secret = PotentialSecret('test box', 'test filename', BOX_CLIENT_SECRET)

        assert BoxDetector().verify(
            BOX_CLIENT_SECRET,
            '''"clientID": "{}",
               "clientSecret": "{}",
               "privateKey": "{}",
               "passphrase": "{}",
               "enterpriseID": "{}"
            '''.format(
                BOX_CLIENT_ID, BOX_CLIENT_SECRET,
                BOX_PRIVATE_KEY, BOX_PASSPHRASE, BOX_ENTERPRISE_ID,
            ),
            potential_secret,
        ) == VerifiedResult.UNVERIFIED

    @patch('detect_secrets.plugins.box.JWTAuth')
    @patch('detect_secrets.plugins.box.Client')
    def test_verify_unverified_missing_passphrase(self, mock_box, mock_jwt):
        mock_box.side_effect = Exception('oops')

        potential_secret = PotentialSecret('test box', 'test filename', BOX_CLIENT_SECRET)

        assert BoxDetector().verify(
            BOX_CLIENT_SECRET,
            '''"clientID": "{}",
               "clientSecret": "{}",
               "publicKeyID": "{}",
               "privateKey": "{}",
               "enterpriseID": "{}"
            '''.format(
                BOX_CLIENT_ID, BOX_CLIENT_SECRET, BOX_PUBLIC_KEY_ID,
                BOX_PRIVATE_KEY, BOX_ENTERPRISE_ID,
            ),
            potential_secret,
        ) == VerifiedResult.UNVERIFIED

    @patch('detect_secrets.plugins.box.JWTAuth')
    @patch('detect_secrets.plugins.box.Client')
    def test_verify_unverified_missing_privatekey(self, mock_box, mock_jwt):
        mock_box.side_effect = Exception('oops')

        potential_secret = PotentialSecret('test box', 'test filename', BOX_CLIENT_SECRET)

        assert BoxDetector().verify(
            BOX_CLIENT_SECRET,
            '''"clientID": "{}",
               "clientSecret": "{}",
               "publicKeyID": "{}",
               "passphrase": "{}",
               "enterpriseID": "{}"
            '''.format(
                BOX_CLIENT_ID, BOX_CLIENT_SECRET, BOX_PUBLIC_KEY_ID,
                BOX_PASSPHRASE, BOX_ENTERPRISE_ID,
            ),
            potential_secret,
        ) == VerifiedResult.UNVERIFIED

    @patch('detect_secrets.plugins.box.JWTAuth')
    @patch('detect_secrets.plugins.box.Client')
    def test_verify_unverified_missing_enterpriseid(self, mock_box, mock_jwt):
        mock_box.side_effect = Exception('oops')

        potential_secret = PotentialSecret('test box', 'test filename', BOX_CLIENT_SECRET)

        assert BoxDetector().verify(
            BOX_CLIENT_SECRET,
            '''"clientID": "{}",
               "clientSecret": "{}",
               "publicKeyID": "{}",
               "privateKey": "{}",
               "passphrase": "{}",
            '''.format(
                BOX_CLIENT_ID, BOX_CLIENT_SECRET, BOX_PUBLIC_KEY_ID,
                BOX_PRIVATE_KEY, BOX_PASSPHRASE,
            ),
            potential_secret,
        ) == VerifiedResult.UNVERIFIED

    @pytest.mark.parametrize(
        'content, prefix_regex, factor_keyword_regex, factor_regex, expected_result',
        (
            (
                '"clientID": "abcd1234abcd1234abcd1234abcd1234"',
                BoxDetector().clientid_prefix,
                BoxDetector().clientid_factor_keyword,
                BoxDetector().clientid_factor,
                ['abcd1234abcd1234abcd1234abcd1234'],
            ),
            (
                '"publicKeyID": "abcd1234"',
                BoxDetector().publickeyid_prefix,
                BoxDetector().publickeyid_factor_keyword,
                BoxDetector().publickeyid_factor,
                ['abcd1234'],
            ),
            (
                '"privateKey": "-----BEGIN ENCRYPTED PRIVATE KEY-----'
                + ' key -----END ENCRYPTED PRIVATE KEY-----\n"',
                BoxDetector().privatekey_prefix,
                BoxDetector().privatekey_factor_keyword,
                BoxDetector().privatekey_factor,
                ['-----BEGIN ENCRYPTED PRIVATE KEY----- key -----END ENCRYPTED PRIVATE KEY-----'],
            ),
            (
                '"passphrase": "abcd1234abcd1234abcd1234abcd1234"',
                BoxDetector().passphrase_prefix,
                BoxDetector().passphrase_factor_keyword,
                BoxDetector().passphrase_factor,
                ['abcd1234abcd1234abcd1234abcd1234'],
            ),
            (
                '"enterpriseID": "1234"',
                BoxDetector().enterpriseid_prefix,
                BoxDetector().enterpriseid_factor_keyword,
                BoxDetector().enterpriseid_factor,
                ['1234'],
            ),
        ),
    )
    def test_find_other_factor(
        self, content, prefix_regex, factor_keyword_regex, factor_regex, expected_result,
    ):
        assert find_other_factor(
            content, prefix_regex, factor_keyword_regex, factor_regex,
        ) == expected_result
