from __future__ import absolute_import
from __future__ import unicode_literals

from detect_secrets.plugins.core.yaml_file_parser import YamlFileParser
from testing.mocks import mock_file_object


class TestYamlFileParser(object):

    def test_get_ignored_lines(self):
        content = """keyA: value
        keyB: \"another_value\"  # pragma: whitelist secret
        keyC: yet_another_value
        """

        f = mock_file_object(content)

        ignored_lines = YamlFileParser(f).get_ignored_lines()

        assert ignored_lines == {2}
