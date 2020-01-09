from __future__ import absolute_import

import re

import ibm_db

from .base import RegexBasedDetector
from detect_secrets.core.constants import VerifiedResult


class DB2Detector(RegexBasedDetector):
    """ Scans for DB2 Credentials """

    secret_type = 'DB2 Credentials'

    begin = r'(?:(?<=\W)|(?<=^))'
    opt_quote = r'(?:"|\'|)'
    opt_db = r'(?:db2|dashdb|db|)'
    opt_dash_undrscr = r'(?:_|-|)'
    password_keyword = r'(?:password|pwd|pass|passwd)'
    opt_space = r'(?: *)'
    assignment = r'(?:=|:|:=|=>|::)'
    # catch any character except newline and quotations, we exclude these
    # because the regex will erronously match them when present at the end of the password
    # db2 password requirements vary by version so we cast a broad net
    password = r'([^\n"\']+)'
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

    username_keyword_regex = r'(?:user|user(?:_|-|)name|uid|user(?:_|-|)id|u(?:_|-|)name)'
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

    def verify(self, token, content, potential_secret, timeout=5):

        username_matches = find_other_factor(
            content, self.username_keyword_regex,
            self.username_regex,
        )
        if not username_matches:
            return VerifiedResult.UNVERIFIED

        database_matches = find_other_factor(
            content, self.database_keyword_regex,
            self.database_regex,
        )
        port_matches = find_other_factor(
            content, self.port_keyword_regex,
            self.port_regex,
        )
        hostname_matches = find_other_factor(
            content, self.hostname_keyword_regex,
            self.hostname_regex,
        )

        url_matches = get_hostname_port_database_from_url(
            content, self.hostname_regex, self.port_regex, self.database_regex,
        )
        for match in url_matches:
            hostname, port, database = match
            hostname_matches.append(hostname)
            port_matches.append(port)
            database_matches.append(database)

        if not database_matches or not port_matches or not hostname_matches:
            return VerifiedResult.UNVERIFIED

        for username in username_matches:  # pragma: no cover
            for database in database_matches:  # pragma: no cover
                for port in port_matches:  # pragma: no cover
                    for hostname in hostname_matches:  # pragma: no cover
                        verify_result = verify_db2_credentials(
                            database, hostname, port, username, token, timeout,
                        )
                        if verify_result == VerifiedResult.VERIFIED_TRUE:
                            potential_secret.other_factors['database'] = database
                            potential_secret.other_factors['hostname'] = hostname
                            potential_secret.other_factors['port'] = port
                            potential_secret.other_factors['username'] = username
                        return verify_result

        return VerifiedResult.VERIFIED_FALSE


def verify_db2_credentials(
    database, hostname, port, username, password, timeout=5,
):  # pragma: no cover
    try:
        conn_str = 'database={database};hostname={hostname};port={port};' + \
                   'protocol=tcpip;uid={username};pwd={password};' + \
                   'ConnectTimeout={timeout}'
        conn_str = conn_str.format(
            database=database,
            hostname=hostname,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
        )
        ibm_db_conn = ibm_db.connect(conn_str, '', '')
        if ibm_db_conn:
            return VerifiedResult.VERIFIED_TRUE
        else:
            return VerifiedResult.VERIFIED_FALSE
    except Exception as e:
        if 'Timeout' in str(e):
            return VerifiedResult.UNVERIFIED
        else:
            return VerifiedResult.VERIFIED_FALSE


def find_other_factor(content, factor_keyword_regex, factor_regex):
    regex = RegexBasedDetector.assign_regex_generator(
        prefix_regex=DB2Detector.opt_db,
        password_keyword_regex=factor_keyword_regex,
        password_regex=factor_regex,
    )

    return [
        match
        for line in content.splitlines()
        for match in regex.findall(line)
    ]


def get_hostname_port_database_from_url(content, hostname_regex, port_regex, database_regex):
    """
    Gets hostname, port, and database factors from a jdbc db2 url
    Accepts: content to scan, regexes to capture hostname, port, and database
    Returns: list of tuples of format (hostname, port, database),
             or empty list if no matches
    """
    regex = re.compile(
        r'jdbc:db2:\/\/{hostname}:{port}\/{database}'.format(
            hostname=hostname_regex,
            port=port_regex,
            database=database_regex,
        ),
    )

    return [
        (match[0], match[1], match[2])
        for line in content.splitlines()
        for match in regex.findall(line)
    ]
