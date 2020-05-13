from __future__ import absolute_import

from boxsdk import Client
from boxsdk import JWTAuth

from .base import RegexBasedDetector
from detect_secrets.core.constants import VerifiedResult


class BoxDetector(RegexBasedDetector):
    """ Scans for Box credentials """

    secret_type = 'Box Credentials'

    token_prefix = r'(?:client)'
    password_keyword = r'(?:secret)'
    password = r'([a-zA-Z0-9]{32})'  # pragma: whitelist secret
    denylist = (
        RegexBasedDetector.assign_regex_generator(
            prefix_regex=token_prefix,
            password_keyword_regex=password_keyword,
            password_regex=password,
        ),
    )

    clientid_prefix = r'(?:client)'
    clientid_factor_keyword = r'(?:id)'
    clientid_factor = r'([a-z0-9]{32})'

    publickeyid_prefix = r'(?:public(?:-|_|)key)'
    publickeyid_factor_keyword = r'(?:id)'
    publickeyid_factor = r'([a-z0-9]{8})'

    privatekey_prefix = r'(?:private)'
    privatekey_factor_keyword = r'(?:key)'
    privatekey_factor = r'(-----BEGIN ENCRYPTED PRIVATE KEY-----(?:.|\n)+' + \
        r'-----END ENCRYPTED PRIVATE KEY-----(?:\n|))'

    passphrase_prefix = r'(?:pass)'
    passphrase_factor_keyword = r'(?:phrase)'
    passphrase_factor = r'([a-z0-9]{32})'

    enterpriseid_prefix = r'(?:enterprise)'
    enterpriseid_factor_keyword = r'(?:id)'
    enterpriseid_factor = r'([0-9]+)'

    def verify(self, token, content, potential_secret):
        clientid_matches = find_other_factor(
            content, self.clientid_prefix,
            self.clientid_factor_keyword, self.clientid_factor,
        )
        if not clientid_matches:
            return VerifiedResult.UNVERIFIED

        publickeyid_matches = find_other_factor(
            content, self.publickeyid_prefix,
            self.publickeyid_factor_keyword, self.publickeyid_factor,
        )
        if not publickeyid_matches:
            return VerifiedResult.UNVERIFIED

        privatekey_matches = find_other_factor(
            content, self.privatekey_prefix,
            self.privatekey_factor_keyword, self.privatekey_factor,
        )
        if not privatekey_matches:
            return VerifiedResult.UNVERIFIED

        passphrase_matches = find_other_factor(
            content, self.passphrase_prefix,
            self.passphrase_factor_keyword, self.passphrase_factor,
        )
        if not passphrase_matches:
            return VerifiedResult.UNVERIFIED

        enterpriseid_matches = find_other_factor(
            content, self.enterpriseid_prefix,
            self.enterpriseid_factor_keyword, self.enterpriseid_factor,
        )
        if not enterpriseid_matches:
            return VerifiedResult.UNVERIFIED

        for clientid in clientid_matches:
            for publickeyid in publickeyid_matches:
                for privatekey in privatekey_matches:
                    for passphrase in passphrase_matches:
                        for enterpriseid in enterpriseid_matches:
                            # fix private key newlines
                            privatekey = privatekey + '\\n'
                            privatekey = privatekey.replace('\\n', '\n')
                            # validate
                            response = get_box_user(
                                clientid, token, enterpriseid,
                                publickeyid, passphrase, privatekey,
                            )
                            if response:
                                potential_secret.other_factors['clientID'] = clientid
                                potential_secret.other_factors['publicKeyID'] = publickeyid
                                potential_secret.other_factors['privateKey'] = privatekey
                                potential_secret.other_factors['passphrase'] = passphrase
                                potential_secret.other_factors['enterpriseID'] = enterpriseid
                                return VerifiedResult.VERIFIED_TRUE

        return VerifiedResult.VERIFIED_FALSE


def get_box_user(
    clientid, token, enterpriseid,
    publickeyid, passphrase, privatekey,
):
    auth = JWTAuth(
        client_id=clientid,
        client_secret=token,
        enterprise_id=enterpriseid,
        jwt_key_id=publickeyid,
        rsa_private_key_passphrase=passphrase.encode(),
        rsa_private_key_data=privatekey,
    )
    try:
        client = Client(auth)
        return client.user().get().name
    except Exception:
        return None


def find_other_factor(content, prefix_regex, factor_keyword_regex, factor_regex):
    regex = RegexBasedDetector.assign_regex_generator(
        prefix_regex=prefix_regex,
        password_keyword_regex=factor_keyword_regex,
        password_regex=factor_regex,
    )

    return [
        match
        for line in content.splitlines()
        for match in regex.findall(line)
    ]
