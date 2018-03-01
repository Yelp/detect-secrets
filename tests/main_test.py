#!/usr/bin/python
import unittest

import mock

from detect_secrets.main import main
from tests.util.mock_util import Any
from tests.util.mock_util import setup_global_mocks


class MainTest(unittest.TestCase):
    """These are smoke tests for the console usage of detect_secrets.
    Most of the functional test cases should be within their own module tests.
    """

    def setUp(self):
        setup_global_mocks(self, [
            ('detect_secrets.main.print', False)
        ])

    def test_smoke(self):
        assert main([]) == 0

    @mock.patch('detect_secrets.main.initialize')
    def test_initialize_flag_no_excludes_no_rootdir(self, mock_initialize):
        assert main(['--scan']) == 0

        mock_initialize.assert_called_once_with(
            Any(tuple),
            None,
            '.'
        )

    @mock.patch('detect_secrets.main.initialize')
    def test_initialize_flag_with_rootdir(self, mock_initialize):
        assert main([
            '--scan',
            'test_data'
        ]) == 0

        mock_initialize.assert_called_once_with(
            Any(tuple),
            None,
            'test_data'
        )

    @mock.patch('detect_secrets.main.initialize')
    def test_initialize_flag_with_exclude(self, mock_initialize):
        assert main([
            '--scan',
            '--exclude',
            'some_pattern_here'
        ]) == 0

        mock_initialize.assert_called_once_with(
            Any(tuple),
            'some_pattern_here',
            '.'
        )
