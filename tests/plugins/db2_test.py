from __future__ import absolute_import

import textwrap

import pytest
from mock import MagicMock
from mock import patch

from detect_secrets.core.constants import VerifiedResult
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.plugins.db2 import Db2Detector
from detect_secrets.plugins.db2 import find_other_factor
from detect_secrets.plugins.db2 import get_hostname_port_database_from_url


DB2_USER = 'fake_user'
DB2_PASSWORD = 'fake_password'
DB2_PORT = '1234'
DB2_HOSTNAME = 'fake.host.name'
DB2_DATABASE = 'fake_database'
DB2_CONN_STRING = 'database={DB2_DATABASE};hostname={DB2_HOSTNAME};port={DB2_PORT};' + \
                  'protocol=tcpip;uid={DB2_USER};pwd={DB2_PASSWORD};ConnectTimeout=5'
DB2_CONN_STRING = DB2_CONN_STRING.format(
    DB2_DATABASE=DB2_DATABASE,
    DB2_HOSTNAME=DB2_HOSTNAME,
    DB2_PORT=DB2_PORT,
    DB2_USER=DB2_USER,
    DB2_PASSWORD=DB2_PASSWORD,
)


class TestGheDetector(object):

    @pytest.mark.parametrize(
        'token, payload, should_flag',
        [
            (
                'secret',
                'database=test;hostname=host.test.com;'
                'port=1;protocol=tcpip;uid=testid;pwd=secret', True,
            ),
            ('$omespeci@!ch@r$', 'dbpwd=$omespeci@!ch@r$', True),
            ('astring', 'db2_password = "astring"', True),
            ('Iusedb2!', '"password": "Iusedb2!"', True),
            ('ilikespaces', 'password =    "ilikespaces"', True),
            (':anothersyntax!', 'pwd::anothersyntax!', True),
            ('@#!%#', 'DB2_PASSWORD = "@#!%#"', True),
            ('pass', 'dashdb-password = "pass"', True),
            ('', 'dashdb_host = notapassword', False),
            ('', 'someotherpassword = "doesnt start right"', False),
        ],
    )
    def test_analyze_line(self, token, payload, should_flag):
        logic = Db2Detector()

        output = logic.analyze_line(payload, 1, 'mock_filename')
        assert len(output) == int(should_flag)
        if len(output) > 0:
            assert list(output.keys())[0].secret == token

    @patch('detect_secrets.plugins.db2.ibm_db.connect')
    def test_verify_invalid_connect_returns_none(self, mock_db2_connect):
        mock_db2_connect.return_value = None

        potential_secret = PotentialSecret('test db2', 'test filename', DB2_PASSWORD)
        assert Db2Detector().verify(
            DB2_PASSWORD,
            '''user={},
               password={},
               database={},
               host={},
               port={}'''.format(DB2_USER, DB2_PASSWORD, DB2_DATABASE, DB2_HOSTNAME, DB2_PORT),
            potential_secret,
        ) == VerifiedResult.VERIFIED_FALSE

        mock_db2_connect.assert_called_with(DB2_CONN_STRING, '', '')

    @patch('detect_secrets.plugins.db2.ibm_db.connect')
    def test_verify_invalid_connect_throws_exception(self, mock_db2_connect):
        mock_db2_connect.side_effect = Exception('oops')

        potential_secret = PotentialSecret('test db2', 'test filename', DB2_PASSWORD)
        assert Db2Detector().verify(
            DB2_PASSWORD,
            '''user={},
               password={},
               database={},
               host={},
               port={}'''.format(DB2_USER, DB2_PASSWORD, DB2_DATABASE, DB2_HOSTNAME, DB2_PORT),
            potential_secret,
        ) == VerifiedResult.VERIFIED_FALSE

        mock_db2_connect.assert_called_with(DB2_CONN_STRING, '', '')

    @patch('detect_secrets.plugins.db2.ibm_db.connect')
    def test_verify_valid_secret(self, mock_db2_connect):
        mock_db2_connect.return_value = MagicMock()

        potential_secret = PotentialSecret('test db2', 'test filename', DB2_PASSWORD)
        assert Db2Detector().verify(
            DB2_PASSWORD,
            '''user={},
               password={},
               database={},
               host={},
               port={}'''.format(DB2_USER, DB2_PASSWORD, DB2_DATABASE, DB2_HOSTNAME, DB2_PORT),
            potential_secret,
        ) == VerifiedResult.VERIFIED_TRUE

        mock_db2_connect.assert_called_with(DB2_CONN_STRING, '', '')
        assert potential_secret.other_factors['database'] == DB2_DATABASE
        assert potential_secret.other_factors['hostname'] == DB2_HOSTNAME
        assert potential_secret.other_factors['port'] == DB2_PORT
        assert potential_secret.other_factors['username'] == DB2_USER

    @patch('detect_secrets.plugins.db2.ibm_db.connect')
    def test_verify_valid_secret_in_single_quotes(self, mock_db2_connect):
        mock_db2_connect.return_value = MagicMock()

        potential_secret = PotentialSecret('test db2', 'test filename', DB2_PASSWORD)
        assert Db2Detector().verify(
            DB2_PASSWORD,
            '''user='{}',
               password='{}',
               database='{}',
               host='{}',
               port='{}'
            '''.format(DB2_USER, DB2_PASSWORD, DB2_DATABASE, DB2_HOSTNAME, DB2_PORT),
            potential_secret,
        ) == VerifiedResult.VERIFIED_TRUE

        mock_db2_connect.assert_called_with(DB2_CONN_STRING, '', '')
        assert potential_secret.other_factors['database'] == DB2_DATABASE
        assert potential_secret.other_factors['hostname'] == DB2_HOSTNAME
        assert potential_secret.other_factors['port'] == DB2_PORT
        assert potential_secret.other_factors['username'] == DB2_USER

    @patch('detect_secrets.plugins.db2.ibm_db.connect')
    def test_verify_valid_secret_in_double_quotes(self, mock_db2_connect):
        mock_db2_connect.return_value = MagicMock()

        potential_secret = PotentialSecret('test db2', 'test filename', DB2_PASSWORD)
        assert Db2Detector().verify(
            DB2_PASSWORD,
            '''user="{}",
               password="{}",
               database="{}",
               host="{}",
               port="{}"
            '''.format(DB2_USER, DB2_PASSWORD, DB2_DATABASE, DB2_HOSTNAME, DB2_PORT),
            potential_secret,
        ) == VerifiedResult.VERIFIED_TRUE

        mock_db2_connect.assert_called_with(DB2_CONN_STRING, '', '')
        assert potential_secret.other_factors['database'] == DB2_DATABASE
        assert potential_secret.other_factors['hostname'] == DB2_HOSTNAME
        assert potential_secret.other_factors['port'] == DB2_PORT
        assert potential_secret.other_factors['username'] == DB2_USER

    @patch('detect_secrets.plugins.db2.ibm_db.connect')
    def test_verify_from_url(self, mock_db2_connect):
        mock_db2_connect.return_value = MagicMock()

        potential_secret = PotentialSecret('test db2', 'test filename', DB2_PASSWORD)
        assert Db2Detector().verify(
            DB2_PASSWORD,
            '''user={},
               password={},
               url=jdbc:db2://{}:{}/{},
            '''.format(DB2_USER, DB2_PASSWORD, DB2_HOSTNAME, DB2_PORT, DB2_DATABASE),
            potential_secret,
        ) == VerifiedResult.VERIFIED_TRUE

        mock_db2_connect.assert_called_with(DB2_CONN_STRING, '', '')
        assert potential_secret.other_factors['database'] == DB2_DATABASE
        assert potential_secret.other_factors['hostname'] == DB2_HOSTNAME
        assert potential_secret.other_factors['port'] == DB2_PORT
        assert potential_secret.other_factors['username'] == DB2_USER

    @patch('detect_secrets.plugins.db2.ibm_db.connect')
    def test_verify_times_out(self, mock_db2_connect):
        mock_db2_connect.side_effect = Exception('Timeout')

        potential_secret = PotentialSecret('test db2', 'test filename', DB2_PASSWORD)
        assert Db2Detector().verify(
            DB2_PASSWORD,
            '''user={},
               password={},
               database={},
               host={},
               port={}'''.format(DB2_USER, DB2_PASSWORD, DB2_DATABASE, DB2_HOSTNAME, DB2_PORT),
            potential_secret,
        ) == VerifiedResult.UNVERIFIED

        mock_db2_connect.assert_called_with(DB2_CONN_STRING, '', '')

    def test_verify_no_other_factors(self):
        potential_secret = PotentialSecret('test db2', 'test filename', DB2_PASSWORD)
        assert Db2Detector().verify(
            DB2_PASSWORD,
            'password={}'.format(DB2_PASSWORD),
            potential_secret,
        ) == VerifiedResult.UNVERIFIED


@pytest.mark.parametrize(
    'content, factor_keyword_regex, factor_regex, expected_output',
    (
        (
            textwrap.dedent("""
                user = {}
            """)[1:-1].format(
                DB2_USER,
            ),
            Db2Detector().username_keyword_regex,
            Db2Detector().username_regex,
            [DB2_USER],
        ),
        (
            textwrap.dedent("""
                port = {}
            """)[1:-1].format(
                DB2_PORT,
            ),
            Db2Detector().port_keyword_regex,
            Db2Detector().port_regex,
            [DB2_PORT],
        ),
        (
            textwrap.dedent("""
                database = {}
            """)[1:-1].format(
                DB2_DATABASE,
            ),
            Db2Detector().database_keyword_regex,
            Db2Detector().database_regex,
            [DB2_DATABASE],
        ),
        (
            textwrap.dedent("""
                host = {}
            """)[1:-1].format(
                DB2_HOSTNAME,
            ),
            Db2Detector().hostname_keyword_regex,
            Db2Detector().hostname_regex,
            [DB2_HOSTNAME],
        ),
    ),
)
def test_find_other_factor(content, factor_keyword_regex, factor_regex, expected_output):
    assert find_other_factor(content, factor_keyword_regex, factor_regex) == expected_output


@pytest.mark.parametrize(
    'content, hostname_regex, port_regex, database_regex, expected_output',
    (
        (
            textwrap.dedent("""
                jdbc:db2://{}:{}/{}
            """)[1:-1].format(
                DB2_HOSTNAME,
                DB2_PORT,
                DB2_DATABASE,
            ),
            Db2Detector().hostname_regex,
            Db2Detector().port_regex,
            Db2Detector().database_regex,
            [(DB2_HOSTNAME, DB2_PORT, DB2_DATABASE)],
        ),
        (
            textwrap.dedent("""
                jdbc:db2://{}:{}/
            """)[1:-1].format(
                DB2_HOSTNAME,
                DB2_PORT,
            ),
            Db2Detector().hostname_regex,
            Db2Detector().port_regex,
            Db2Detector().database_regex,
            [],
        ),
        (
            textwrap.dedent("""
                nonsense
            """),
            Db2Detector().hostname_regex,
            Db2Detector().port_regex,
            Db2Detector().database_regex,
            [],
        ),
    ),
)
def test_get_hostname_port_database_from_url(
        content, hostname_regex, port_regex, database_regex, expected_output,
):
    assert get_hostname_port_database_from_url(
        content, hostname_regex, port_regex, database_regex,
    ) == expected_output
