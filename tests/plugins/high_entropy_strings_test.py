from __future__ import absolute_import
from __future__ import unicode_literals

import codecs

import pytest

from detect_secrets.plugins.high_entropy_strings import Base64HighEntropyString
from detect_secrets.plugins.high_entropy_strings import HexHighEntropyString
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
        'content_to_format, should_be_caught',
        [
            (
                "'{non_secret}'",
                False,
            ),
            (
                "'{secret}'",
                True,
            ),
            # Matches exclude_lines_regex
            (
                'CanonicalUser: {secret}',
                False,
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

        assert len(results) == should_be_caught

    @pytest.mark.parametrize(
        'content_to_format, expected_results',
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
            # Test inline annotation for allowlisting
            "'{secret}'  # pragma: allowlist secret",
            "'{secret}'  # pragma: allowlist secret more text",
            "'{secret}' #  pragma: allowlist secret",
            "'{secret}'  // pragma: allowlist secret",
            "'{secret}' //  pragma: allowlist secret",
            "'{secret}'  /* pragma: allowlist secret */",
            "'{secret}'  /* pragma: allowlist secret more text */",
            "'{secret}' /*  pragma: allowlist secret  */",
            "'{secret}'  ' pragma: allowlist secret",
            "'{secret}' '  pragma: allowlist secret",
            "'{secret}'  -- pragma: allowlist secret",
            "'{secret}' --  pragma: allowlist secret",
            "'{secret}' <!--pragma: allowlist secret-->",
            "'{secret}' <!-- # pragma: allowlist secret -->",
            "'{secret}' <!-- pragma: allowlist secret -->",
            "'{secret}' <!--  pragma: allowlist secret  -->",
            # Test old inline annotation for backwards compatibility
            "'{secret}'  # pragma: whitelist secret",
            # Test high entropy exclude regex
            '"CanonicalUser": "{secret}"',
            # Not a string
            '{secret}',
        ],
    )
    def test_ignored_lines(self, content_to_format):
        file_content = content_to_format.format(secret=self.secret)
        f = mock_file_object(file_content)

        results = self.logic.analyze(f, 'does_not_matter')

        assert len(results) == 0

    def test_entropy_lower_limit(self):
        with pytest.raises(ValueError):
            Base64HighEntropyString(-1)

    def test_entropy_upper_limit(self):
        with pytest.raises(ValueError):
            Base64HighEntropyString(15)


class TestRegularBase64HighEntropyStrings(HighEntropyStringsTest):

    def setup(self):
        super(TestRegularBase64HighEntropyStrings, self).setup(
            # Testing default limit, as suggested by truffleHog.
            logic=Base64HighEntropyString(
                base64_limit=4.5,
                exclude_lines_regex='CanonicalUser',
            ),
            non_secret_string='c3VwZXIgc2VjcmV0IHZhbHVl',  # Too short for high entropy
            secret_string='c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5',
        )

    @pytest.mark.parametrize(
        'filename, secrets',
        [
            (
                'test_data/config.ini',
                [
                    'Location:    test_data/config.ini:2',
                    'Location:    test_data/config.ini:6',
                    'Location:    test_data/config.ini:10',
                    'Location:    test_data/config.ini:15',
                    'Location:    test_data/config.ini:21',
                    'Location:    test_data/config.ini:22',
                ],
            ),
            (
                'test_data/files/file_with_secrets.py',
                ['Location:    test_data/files/file_with_secrets.py:3'],
            ),
            # Mark down files with colons and unicode charaters preceding the
            # colon on the line would cause the scanner to fail and exit on
            # 2.7 due to ini parser being used on non-markdown files
            # this test case ensure that scanning can complete and find
            # high entropy issues
            (
                'test_data/config.md',
                ['Location:    test_data/config.md:10'],
            ),
        ],
    )
    def test_ini_file(self, filename, secrets):
        # We're testing two files here, because we want to make sure that
        # the HighEntropyStrings regex is reset back to normal after
        # scanning the ini file.

        plugin = Base64HighEntropyString(3)

        accumulated_secrets = {}
        with codecs.open(filename, encoding='utf-8') as f:
            accumulated_secrets.update(
                plugin.analyze(f, filename),
            )

        count = 0
        for secret in accumulated_secrets.values():
            location = str(secret).splitlines()[1]
            assert location in secrets
            count += 1

        assert count == len(secrets)

    def test_yaml_files(self):
        plugin = Base64HighEntropyString(
            base64_limit=3,
            exclude_lines_regex='CanonicalUser',
        )

        with open('test_data/config.yaml') as f:
            secrets = plugin.analyze(f, 'test_data/config.yaml')

        assert len(secrets.values()) == 3
        for secret in secrets.values():
            location = str(secret).splitlines()[1]
            assert location in (
                'Location:    test_data/config.yaml:3',
                'Location:    test_data/config.yaml:6',
                'Location:    test_data/config.yaml:15',
            )

        with open('test_data/only_comments.yaml') as f:
            secrets = plugin.analyze(f, 'test_data/only_comments.yaml')
        assert not secrets.values()

    def test_env_file(self):
        plugin = Base64HighEntropyString(4.5)
        with open('test_data/config.env') as f:
            secrets = plugin.analyze(f, 'test_data/config.env')

        assert len(secrets.values()) == 1
        for secret in secrets.values():
            location = str(secret).splitlines()[1]
            assert location in (
                'Location:    test_data/config.env:1',
            )


class TestUrlSafeBase64HighEntropyStrings(HighEntropyStringsTest):
    def setup(self):
        super(TestUrlSafeBase64HighEntropyStrings, self).setup(
            # Testing default limit, as suggested by truffleHog.
            logic=Base64HighEntropyString(
                base64_limit=4.5,
                exclude_lines_regex='CanonicalUser',
            ),
            non_secret_string='Zrm-ySTAq7D2sHk=',  # too short for high entropy
            secret_string='I6FwzQZFL9l-44nviI1F04OTmorMaVQf9GS4Oe07qxL_vNkW6CRas4Lo42vqJMT0M6riJfma_f-pTAuoX2U=',  # noqa: E501
        )


class HexHighEntropyStringsWithStandardEntropy(HexHighEntropyString):
    """Copies the HexHighEntropyString class, but keeps the standard
    Shannon entropy calculation.
    """

    def __init__(self, *args, **kwargs):
        super(HexHighEntropyStringsWithStandardEntropy, self).__init__(
            *args,
            **kwargs
        )

    def calculate_shannon_entropy(self, data):
        return super(HexHighEntropyString, self).calculate_shannon_entropy(data)


class TestHexHighEntropyStrings(HighEntropyStringsTest):

    def setup(self):
        super(TestHexHighEntropyStrings, self).setup(
            # Testing default limit, as suggested by truffleHog.
            logic=HexHighEntropyString(
                hex_limit=3,
                exclude_lines_regex='CanonicalUser',
            ),
            non_secret_string='aaaaaa',
            secret_string='2b00042f7481c7b056c4b410d28f33cf',
        )

    def test_yaml_file(self):
        plugin = HexHighEntropyString(3)
        with open('test_data/config2.yaml') as f:
            secrets = plugin.analyze(f, 'test_data/config2.yaml')

        assert len(secrets.values()) == 1
        for secret in secrets.values():
            location = str(secret).splitlines()[1]
            assert location in (
                'Location:    test_data/config2.yaml:2',
            )

    def test_discounts_when_all_numbers(self):
        original_scanner = HexHighEntropyStringsWithStandardEntropy(
            hex_limit=3,
            exclude_lines_regex=None,
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
        assert self.logic.calculate_shannon_entropy('0') == \
            original_scanner.calculate_shannon_entropy('0')
