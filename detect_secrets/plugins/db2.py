from __future__ import absolute_import

import re

import ibm_db

from .base import RegexBasedDetector
from detect_secrets.core.constants import VerifiedResult


class DB2Detector(RegexBasedDetector):

    secret_type = 'DB2 Credentials'

    begin = r'(?:(?<=\W)|(?<=^))'
    opt_quote = r'(?:"|\'|)'
    opt_db = r'(?:db2|dashdb|db|)'
    opt_dash_undrscr = r'(?:_|-|)'
    password_keyword = r'(?:password|pwd|pass|passwd)'
    opt_space = r'(?: *)'
    assignment = r'(?:=|:|:=|=>|::)'
    password = r'[^\n]+'
    denylist = (
        re.compile(
            r'{begin}{opt_quote}{opt_db}{opt_dash_undrscr}{password_keyword}{opt_quote}{opt_space}'
            '{assignment}{opt_space}{opt_quote}{password}{opt_quote}'.format(
                begin=begin,
                opt_quote=opt_quote,
                opt_db=opt_db,
                opt_dash_undrscr=opt_dash_undrscr,
                password_keyword=password_keyword,
                opt_space=opt_space,
                assignment=assignment,
                password=password,
            ), flags=re.IGNORECASE,
        ),
    )

    username_keyword_regex = r'(?:user|user(?:_|-|)name|uid|user(?:_|-|)id)'
    username_regex = r'([a-zA-Z0-9_]+)'

    database_keyword_regex = r'(?:database|db|database(?:_|-|)name|db(?:_|-|)name)'
    database_regex = r'([a-zA-Z0-9_-]+)'

    port_keyword_regex = r'(?:port|port(?:_|-|)number)'
    port_regex = r'([0-9]{1,5})'

    hostname_keyword_regex = (
        r'(?:host|host(?:_|-|)name|host(?:_|-|)address|'
        r'host(?:_|-|)ip|host(?:_|-|)ip(?:_|-|)address)'
    )
    hostname_regex = (
        r'((?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)'
        r'*(?:.\[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]))'
    )

    def verify(self, token, content, potential_secret=None):

        username_matches = get_other_factor(
            content, self.username_keyword_regex,
            self.username_regex,
        )
        database_matches = get_other_factor(
            content, self.database_keyword_regex,
            self.database_regex,
        )
        port_matches = get_other_factor(
            content, self.port_keyword_regex,
            self.port_regex,
        )
        hostname_matches = get_other_factor(
            content, self.hostname_keyword_regex,
            self.hostname_regex,
        )

        if not username_matches or not database_matches or not port_matches or not hostname_matches:
            return VerifiedResult.UNVERIFIED

        for username in username_matches:  # pragma: no cover
            for database in database_matches:  # pragma: no cover
                for port in port_matches:  # pragma: no cover
                    for hostname in hostname_matches:  # pragma: no cover
                        verify_result = verify_db2_credentials(
                            database, hostname, port, username, token,
                        )
                        if verify_result == VerifiedResult.VERIFIED_TRUE:
                            potential_secret.other_factors['database'] = database
                            potential_secret.other_factors['hostname'] = hostname
                            potential_secret.other_factors['port'] = port
                            potential_secret.other_factors['username'] = username
                        return verify_result

        return VerifiedResult.VERIFIED_FALSE


def verify_db2_credentials(database, hostname, port, username, password):  # pragma: no cover
    try:
        conn_str = 'database={database};hostname={hostname};port={port};' + \
                   'protocol=tcpip;uid={username};pwd={password}'
        conn_str = conn_str.format(
            database=database,
            hostname=hostname,
            port=port,
            username=username,
            password=password,
        )
        ibm_db_conn = ibm_db.connect(conn_str, '', '')
        if ibm_db_conn:
            return VerifiedResult.VERIFIED_TRUE
        else:
            return VerifiedResult.VERIFIED_FALSE
    except Exception:
        return VerifiedResult.UNVERIFIED


def get_other_factor(content, factor_keyword_regex, factor_regex):
    begin = r'(?:(?<=\W)|(?<=^))'
    opt_quote = r'(?:"|\'|)'
    opt_db = r'(?:db2|dashdb|db|)'
    opt_dash_undrscr = r'(?:_|-|)'
    opt_space = r'(?: *)'
    assignment = r'(?:=|:|:=|=>|::)'
    regex = re.compile(
        r'{begin}{opt_quote}{opt_db}{opt_dash_undrscr}{factor_keyword}{opt_quote}{opt_space}'
        '{assignment}{opt_space}{opt_quote}{factor}{opt_quote}'.format(
            begin=begin,
            opt_quote=opt_quote,
            opt_db=opt_db,
            opt_dash_undrscr=opt_dash_undrscr,
            factor_keyword=factor_keyword_regex,
            opt_space=opt_space,
            assignment=assignment,
            factor=factor_regex,
        ), flags=re.IGNORECASE,
    )

    return [
        match
        for line in content.splitlines()
        for match in regex.findall(line)
    ]
