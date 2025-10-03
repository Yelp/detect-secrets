import re
from unittest import mock

import pytest
import requests

from detect_secrets import main as main_module
from detect_secrets.constants import VerifiedResult
from detect_secrets.plugins.base import RegexBasedDetector
from testing.mocks import mock_printer
from testing.plugins import register_plugin


class TestVerify:
    @staticmethod
    def test_does_not_verify_if_no_verify():
        with register_plugin(MockPlugin(should_verify=False)):
            main_module.main(['scan', '--string', 'deadbeef', '--no-verify'])

    @staticmethod
    @pytest.mark.parametrize(
        'args, verified_result, should_be_present',
        (
            ([], VerifiedResult.UNVERIFIED, True),
            ([], VerifiedResult.VERIFIED_TRUE, True),
            (['--only-verified'], VerifiedResult.UNVERIFIED, False),
            (['--only-verified'], VerifiedResult.VERIFIED_TRUE, True),
        ),
    )
    def test_adheres_to_verification_policies(args, verified_result, should_be_present):
        with register_plugin(
            MockPlugin(verified_result=verified_result),
        ), mock_printer(main_module) as printer:
            main_module.main(['scan', '--string', 'deadbeef', *args])

        for line in printer.message.splitlines():
            plugin_name, result = [x.strip() for x in line.split(':')]
            if plugin_name != 'MockPlugin':
                continue

            assert should_be_present == result.startswith('True')

    @staticmethod
    def test_supports_injection_of_context():
        # NOTE: This test case relies on the fact that this file contains a multi-factor
        # AWS KeyPair.
        with register_plugin(ContextAwareMockPlugin()):
            with mock.patch(
                'detect_secrets.plugins.aws.verify_aws_secret_access_key',
                return_value=False,
            ):

                main_module.main(['scan', 'test_data/each_secret.py'])

    @staticmethod
    def test_handles_request_error_gracefully():
        with register_plugin(ExceptionRaisingMockPlugin()):
            main_module.main(['scan', '--string', 'fake-secret'])


class MockPlugin(RegexBasedDetector):
    denylist = (
        # We use a hex string here, due to the gibberish detector.
        re.compile('deadbeef'),
    )
    secret_type = 'mock plugin'

    def __init__(self, should_verify=True, verified_result=VerifiedResult.UNVERIFIED):
        self.should_verify = should_verify
        self.verified_result = verified_result

    def verify(self, secret):
        if not self.should_verify:
            raise AssertionError('Verification should not occur.')

        return self.verified_result


class ContextAwareMockPlugin(MockPlugin):
    def verify(self, secret, context):
        return VerifiedResult.UNVERIFIED


class ExceptionRaisingMockPlugin(MockPlugin):
    def verify(self, secret):
        raise requests.exceptions.ConnectionError


class TestIsBaselineFile:
    """Tests for is_baseline_file filter (issue #912)."""
    
    def test_absolute_path(self):
        """Test that absolute paths are normalized correctly."""
        from detect_secrets.filters.common import is_baseline_file
        from detect_secrets.settings import get_settings
        import os
        import tempfile
        
        with tempfile.NamedTemporaryFile(suffix='.baseline') as f:
            # Configure the filter with absolute path
            get_settings().filters['detect_secrets.filters.common.is_baseline_file'] = {
                'filename': f.name
            }
            
            # Test with the same absolute path
            assert is_baseline_file(f.name)
            
    def test_relative_path_with_dot_slash(self):
        """Test that ./filename is normalized to filename."""
        from detect_secrets.filters.common import is_baseline_file
        from detect_secrets.settings import get_settings
        import os
        import tempfile
        
        with tempfile.NamedTemporaryFile(suffix='.baseline', delete=False) as f:
            baseline_path = f.name
        
        try:
            orig_cwd = os.getcwd()
            os.chdir(os.path.dirname(baseline_path))
            
            # Configure filter with ./ prefix
            relative_path = './' + os.path.basename(baseline_path)
            get_settings().filters['detect_secrets.filters.common.is_baseline_file'] = {
                'filename': relative_path
            }
            
            # Test that both paths match
            assert is_baseline_file(relative_path)
            assert is_baseline_file(os.path.basename(baseline_path))
            assert is_baseline_file(baseline_path)
            
        finally:
            os.chdir(orig_cwd)
            os.unlink(baseline_path)
    
    def test_normalized_vs_unnormalized_paths(self):
        """Test that paths with redundant separators are normalized."""
        from detect_secrets.filters.common import is_baseline_file
        from detect_secrets.settings import get_settings
        import os
        import tempfile
        
        with tempfile.NamedTemporaryFile(suffix='.baseline', delete=False) as f:
            baseline_path = f.name
        
        try:
            # Configure filter with one path
            get_settings().filters['detect_secrets.filters.common.is_baseline_file'] = {
                'filename': baseline_path
            }
            
            # Test with various normalized forms
            assert is_baseline_file(baseline_path)
            assert is_baseline_file(os.path.realpath(baseline_path))
            assert is_baseline_file(os.path.normpath(baseline_path))
            
        finally:
            os.unlink(baseline_path)
