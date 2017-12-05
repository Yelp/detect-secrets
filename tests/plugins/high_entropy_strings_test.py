#!/usr/bin/python
from __future__ import absolute_import

import unittest

from detect_secrets.plugins.high_entropy_strings import Base64HighEntropyString
from detect_secrets.plugins.high_entropy_strings import HexHighEntropyString
from tests.util.file_util import create_file_object_from_string


def abstract_test_case(func):
    """Decorator used to specify test cases that should NOT be run as part
    of the base test case, but only run by children test cases"""

    def decorator(*args, **kwargs):
        self = args[0]

        if self.__class__.__name__ == 'HighEntropyStringsTest':
            return

        func(*args, **kwargs)

    return decorator


class HighEntropyStringsTest(unittest.TestCase):

    def setUp(self, *args):
        """
        :param plugin:     HighEntropyStringsPlugin
        :param non_secret: string; a hash that will be ignored by plugin.
        :param secret:     string; a hash that will be caught by plugin.
        """
        if len(args) == 3:
            self.logic, self.non_secret, self.secret = args

    def run_test(self, cases):
        """For DRYer code.

        :param cases: list of test cases.
                      Each test case should be in the format:
                      [file_content :string, should_be_caught :boolean]
        """
        for case in cases:
            file_content, should_be_caught = case
            f = create_file_object_from_string(file_content)

            results = self.logic.analyze(f, 'does_not_matter')

            if should_be_caught:
                assert len(results) == 1
            else:
                assert len(results) == 0

    @abstract_test_case
    def test_analyze_multiple_strings_same_line(self):
        cases = [
            (
                'String #1: "%s"; String #2: "%s"' % (self.non_secret, self.secret),
                1,
            ),
            (
                # We add an 'a' to make the second secret different
                'String #1: "%s"; String #2: "%s"' % (self.secret, self.secret + 'a'),
                2,
            ),
        ]

        for case in cases:
            file_content, expected_results = case
            f = create_file_object_from_string(file_content)

            results = self.logic.analyze(f, 'does_not_matter')

            assert len(results) == expected_results

    @abstract_test_case
    def test_ignored_lines(self):
        cases = [
            (
                # Test inline annotation for whitelisting
                "'%s' # pragma: whitelist secret" % self.secret
            ),
            (
                # Not a string
                "%s" % self.secret
            ),
        ]

        for case in cases:
            file_content = case
            f = create_file_object_from_string(file_content)

            results = self.logic.analyze(f, 'does_not_matter')

            assert len(results) == 0


class Base64HighEntropyStringsTest(HighEntropyStringsTest):

    def setUp(self):
        super(Base64HighEntropyStringsTest, self).setUp(
            # Testing default limit, as suggested by truffleHog.
            Base64HighEntropyString(4.5),
            'c3VwZXIgc2VjcmV0IHZhbHVl',     # too short for high entropy
            'c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5',
        )

    def test_pattern(self):
        cases = [
            ("'%s'" % self.non_secret, False),
            ("'%s'" % self.secret, True)
        ]

        self.run_test(cases)


class HexHighEntropyStringsTest(HighEntropyStringsTest):

    def setUp(self):
        super(HexHighEntropyStringsTest, self).setUp(
            # Testing default limit, as suggested by truffleHog.
            HexHighEntropyString(3),
            'aaaaaa',
            '2b00042f7481c7b056c4b410d28f33cf',
        )

    def test_pattern(self):
        cases = [
            ("'%s'" % self.non_secret, False),
            ("'%s'" % self.secret, True)
        ]

        self.run_test(cases)
