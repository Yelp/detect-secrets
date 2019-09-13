from __future__ import absolute_import

import pytest

from detect_secrets.plugins.db2 import DB2Detector


class TestGHDetector(object):

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            (
                'database=test;hostname=host.test.com;'
                'port=1;protocol=tcpip;uid=testid;pwd=secret', True,
            ),
            ('dbpwd=$omespeci@!ch@r$', True),
            ('db2_password = "astring"', True),
            ('"password": "Iusedb2!"', True),
            ('password =    "ilikespaces"', True),
            ('pwd::anothersyntax!', True),
            ('DB2_PASSWORD = "@#!%#"', True),
            ('dashdb-password = "pass"', True),
            ('dashdb_host = notapassword', False),
            ('someotherpassword = "doesnt start right"', False),
        ],
    )
    def test_analyze_string(self, payload, should_flag):
        logic = DB2Detector()

        output = logic.analyze_string(payload, 1, 'mock_filename')
        assert len(output) == int(should_flag)
