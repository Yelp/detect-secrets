from __future__ import absolute_import

import unittest

import mock

from detect_secrets.plugins import initialize
from detect_secrets.plugins import SensitivityValues
from detect_secrets.plugins.high_entropy_strings import Base64HighEntropyString
from detect_secrets.plugins.high_entropy_strings import HexHighEntropyString
from detect_secrets.plugins.private_key import PrivateKeyDetector


class TestInitPlugins(unittest.TestCase):

    def test_initialize_plugins_valid(self):
        plugins = SensitivityValues(
            base64_limit=4.5,
            hex_limit=3,
        )

        output = initialize(plugins)
        assert isinstance(output[0], Base64HighEntropyString)
        assert output[0].entropy_limit == 4.5
        assert isinstance(output[1], HexHighEntropyString)
        assert output[1].entropy_limit == 3

    def test_initialize_plugins_not_base_plugin(self):
        output = initialize({'CustomLog': 4, })
        assert len(output) == 0

    def test_initialize_plugins_failed_instantiation(self):
        plugins = SensitivityValues(
            hex_limit=3,
        )

        with mock.patch('detect_secrets.plugins.HexHighEntropyString.__init__') as m:
            m.side_effect = TypeError

            output = initialize(plugins)

        assert len(output) == 0

    def test_no_sensitivity_value_necessary_plugin(self):
        data = {
            'PrivateKeyDetector': True,
        }
        plugins = SensitivityValues(**data)

        output = initialize(plugins)
        assert len(output) == 1
        assert isinstance(output[0], PrivateKeyDetector)

    def test_disable_plugin_with_false_value(self):
        data = {
            'PrivateKeyDetector': False,
        }
        plugins = SensitivityValues(**data)

        assert len(initialize(plugins)) == 0
