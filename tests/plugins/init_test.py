from __future__ import absolute_import

import mock

from detect_secrets.plugins import initialize
from detect_secrets.plugins import SensitivityValues
from detect_secrets.plugins.high_entropy_strings import Base64HighEntropyString
from detect_secrets.plugins.high_entropy_strings import HexHighEntropyString
from detect_secrets.plugins.private_key import PrivateKeyDetector


class TestInitializePlugins(object):

    def test_success(self):
        plugins = SensitivityValues(
            base64_limit=4.5,
            hex_limit=3,
        )

        output = initialize(plugins)
        assert isinstance(output[0], Base64HighEntropyString)
        assert output[0].entropy_limit == 4.5
        assert isinstance(output[1], HexHighEntropyString)
        assert output[1].entropy_limit == 3

    def test_input_requires_sensitivity_values_object(self):
        assert len(initialize('this is not a SensitivityValues object')) == 0

    def test_false_disables_plugin(self):
        output = initialize(SensitivityValues(PrivateKeyDetector=False))

        assert len(output) == 0

    def test_no_sensitivity_value_necessary_plugin(self):
        plugins = SensitivityValues(PrivateKeyDetector=True)

        output = initialize(plugins)
        assert len(output) == 1
        assert isinstance(output[0], PrivateKeyDetector)

    def test_initialize_plugins_failed_instantiation(self):
        with mock.patch(
            'detect_secrets.plugins.HexHighEntropyString.__init__',
            side_effect=TypeError
        ):
            output = initialize(
                SensitivityValues(
                    hex_limit=3,
                )
            )

        assert len(output) == 0

    def test_aliases(self):
        """For better usability, we can also use aliases when initializing
        the SensitivityValues object.
        """
        plugins = SensitivityValues(
            Base64HighEntropyString=2,

            # Non aliases should take precedence over aliases.
            HexHighEntropyString=1,
            hex_limit=1.5,
        )

        output = initialize(plugins)
        assert isinstance(output[0], Base64HighEntropyString)
        assert output[0].entropy_limit == 2
        assert isinstance(output[1], HexHighEntropyString)
        assert output[1].entropy_limit == 1.5
