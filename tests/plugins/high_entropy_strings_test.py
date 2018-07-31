from __future__ import absolute_import
from __future__ import unicode_literals

import string

import pytest

from detect_secrets.plugins.high_entropy_strings import Base64HighEntropyString
from detect_secrets.plugins.high_entropy_strings import HexHighEntropyString
from detect_secrets.plugins.high_entropy_strings import HighEntropyStringsPlugin
from testing.mocks import mock_file_object


class HighEntropyStringsTest(object):
    """
    Some explaining should be done regarding the "enforced" format of the parametrized
    abstract pytests.

    We want to abstract it, so that the tests would be different for each subclass,
    however, there is no easy way to do that (because pytest marks those fixtures at
    "collection" time -- at which, it has no knowledge of the actual variables).

    Therefore, as a workaround, we provide string formats as the parameterized variable,
    and call `.format` on it at a later time.
    """

    def setup(self, logic, non_secret_string, secret_string):
        """
        :type logic: HighEntropyStringsPlugin
        :param logic: logic used to perform abstracted test cases

        :type non_secret_string: str
        :param non_secret_string: a hash that will be ignored by the plugin

        :type secret_string: str
        :param secret_string: a hash that will be caught by the plugin
        """
        self.logic = logic
        self.non_secret = non_secret_string
        self.secret = secret_string

    @pytest.mark.parametrize(
        'content_to_format,should_be_caught',
        [
            (
                "'{non_secret}'",
                False,
            ),
            (
                "'{secret}'",
                True,
            ),
        ],
    )
    def test_pattern(self, content_to_format, should_be_caught):
        content = content_to_format.format(
            non_secret=self.non_secret,
            secret=self.secret,
        )

        f = mock_file_object(content)

        results = self.logic.analyze(f, 'does_not_matter')

        assert len(results) == bool(should_be_caught)

    @pytest.mark.parametrize(
        'content_to_format,expected_results',
        [
            (
                'String #1: "{non_secret}"; String #2: "{secret}"',
                1,
            ),
            (
                # We add an 'a' to make the second secret different.
                # This currently fits both hex and base64 char set.
                'String #1: "{secret}"; String #2: "{secret}a"',
                2,
            ),
        ],
    )
    def test_analyze_multiple_strings_same_line(self, content_to_format, expected_results):
        content = content_to_format.format(
            non_secret=self.non_secret,
            secret=self.secret,
        )
        f = mock_file_object(content)

        results = self.logic.analyze(f, 'does_not_matter')

        assert len(results) == expected_results

    @pytest.mark.parametrize(
        'content_to_format',
        [
            # Test inline annotation for whitelisting
            "'{secret}' # pragma: whitelist secret",

            # Not a string
            "{secret}",
        ],
    )
    def test_ignored_lines(self, content_to_format):
        file_content = content_to_format.format(secret=self.secret)
        f = mock_file_object(file_content)

        results = self.logic.analyze(f, 'does_not_matter')

        assert len(results) == 0

    def test_ini_file(self):
        # We're testing two files here, because we want to make sure that
        # the HighEntropyStrings regex is reset back to normal after
        # scanning the ini file.
        filenames = [
            'test_data/config.ini',
            'test_data/files/file_with_secrets.py',
        ]

        plugin = Base64HighEntropyString(3)

        accumulated_secrets = {}
        for filename in filenames:
            with open(filename) as f:
                accumulated_secrets.update(
                    plugin.analyze(f, filename),
                )

        count = 0
        for secret in accumulated_secrets.values():
            location = str(secret).splitlines()[1]
            assert location in (
                'Location:    test_data/config.ini:2',
                'Location:    test_data/config.ini:6',
                'Location:    test_data/config.ini:10',
                'Location:    test_data/config.ini:15',
                'Location:    test_data/config.ini:21',
                'Location:    test_data/config.ini:22',
                'Location:    test_data/files/file_with_secrets.py:3',
            )
            count += 1

        assert count == 7

    def test_yaml_file(self):
        plugin = Base64HighEntropyString(3)

        with open('test_data/config.yaml') as f:
            secrets = plugin.analyze(f, 'test_data/config.yaml')

        assert len(secrets.values()) == 1
        for secret in secrets.values():
            location = str(secret).splitlines()[1]
            assert location in (
                'Location:    test_data/config.yaml:3',
            )

    def test_entropy_lower_limit(self):
        with pytest.raises(ValueError):
            Base64HighEntropyString(-1)

    def test_entropy_upper_limit(self):
        with pytest.raises(ValueError):
            Base64HighEntropyString(15)


class TestBase64HighEntropyStrings(HighEntropyStringsTest):

    def setup(self):
        super(TestBase64HighEntropyStrings, self).setup(
            # Testing default limit, as suggested by truffleHog.
            Base64HighEntropyString(4.5),
            'c3VwZXIgc2VjcmV0IHZhbHVl',     # too short for high entropy
            'c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5',
        )


class TestHexHighEntropyStrings(HighEntropyStringsTest):

    def setup(self):
        super(TestHexHighEntropyStrings, self).setup(
            # Testing default limit, as suggested by truffleHog.
            HexHighEntropyString(3),
            'aaaaaa',
            '2b00042f7481c7b056c4b410d28f33cf',
        )

    def test_discounts_when_all_numbers(self):
        original_scanner = HighEntropyStringsPlugin(
            string.hexdigits,
            3,
        )

        # This makes sure discounting works.
        assert self.logic.calculate_shannon_entropy('0123456789') < \
            original_scanner.calculate_shannon_entropy('0123456789')

        # This is the goal.
        assert self.logic.calculate_shannon_entropy('0123456789') < 3

        # This makes sure it is length dependent.
        assert self.logic.calculate_shannon_entropy('0123456789') < \
            self.logic.calculate_shannon_entropy('01234567890123456789')

        # This makes sure it only occurs with numbers.
        assert self.logic.calculate_shannon_entropy('12345a') == \
            original_scanner.calculate_shannon_entropy('12345a')
