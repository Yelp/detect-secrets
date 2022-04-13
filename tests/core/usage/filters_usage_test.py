import uuid

import pytest

from detect_secrets.constants import VerifiedResult
from detect_secrets.core import baseline
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.core.usage import ParserBuilder
from detect_secrets.settings import default_settings
from detect_secrets.settings import get_settings
from detect_secrets.settings import transient_settings
from testing.mocks import mock_named_temporary_file


def test_no_verify_overrides_baseline_settings(parser):
    secrets = SecretsCollection()
    with mock_named_temporary_file() as f, transient_settings({
        'filters_used': [{
            'path': 'detect_secrets.filters.common.is_ignored_due_to_verification_policies',
            'min_level': VerifiedResult.UNVERIFIED.value,
        }],
    }):
        baseline.save_to_file(secrets, f.name)
        f.seek(0)

        parser.parse_args(['scan', '--baseline', f.name, '--no-verify'])
        for filter_path in get_settings().filters:
            assert filter_path.rsplit('.')[-1] != 'is_ignored_due_to_verification_policies'


def test_only_verified_overrides_baseline_settings(parser):
    secrets = SecretsCollection()
    with mock_named_temporary_file() as f, transient_settings({
        'filters_used': [{
            'path': 'detect_secrets.filters.common.is_ignored_due_to_verification_policies',
            'min_level': VerifiedResult.UNVERIFIED.value,
        }],
    }):
        baseline.save_to_file(secrets, f.name)
        f.seek(0)

        parser.parse_args(['scan', '--baseline', f.name, '--only-verified'])
        assert get_settings().filters[
            'detect_secrets.filters.common.is_ignored_due_to_verification_policies'
        ]['min_level'] == VerifiedResult.VERIFIED_TRUE.value


class TestCustomFilters:
    @staticmethod
    @pytest.mark.parametrize(
        'scheme',
        (
            '',
            'file://',
        ),
    )
    @pytest.mark.parametrize(
        'filepath',
        (
            # No function
            'testing/custom_filters.py',

            # Invalid file
            'testing/invalid_file.py::function_name',

            # Invalid function
            'file://testing/custom_filters.py::function_name',
        ),
    )
    def test_local_file_failure(scheme, filepath, parser):
        with pytest.raises(SystemExit):
            parser.parse_args(['scan', '--filter', scheme + filepath])

    @staticmethod
    @pytest.mark.parametrize(
        'scheme',
        (
            '',
            'file://',
        ),
    )
    def test_local_file_success(scheme, parser):
        secrets = SecretsCollection()
        with transient_settings({
            'plugins_used': [{
                'name': 'Base64HighEntropyString',
            }],
        }):
            parser.parse_args([
                'scan',
                '--filter',
                scheme + 'testing/custom_filters.py::is_invalid_secret',
            ])
            secrets.scan_file('test_data/config.env')

        assert not secrets

    @staticmethod
    def test_module_success(parser):
        config = {
            # Remove all filters, so we can test adding things back in.
            'filters_used': [],
        }

        with transient_settings(config):
            default_filters = set(get_settings().filters.keys())

        module_path = 'detect_secrets.filters.heuristic.is_sequential_string'
        assert module_path not in default_filters
        with transient_settings(config):
            parser.parse_args(['scan', '--filter', module_path])
            assert module_path in get_settings().filters

    @staticmethod
    @pytest.mark.parametrize(
        'filepath',
        (
            # Invalid module path
            'detect_secrets.asdf',

            # Not a function
            'detect_secrets.filters.common',

            # Invalid function name
            'detect_secrets.filters.heuristic.IGNORED_FILE_EXTENSIONS',

            # Not a module path.
            'blah',
        ),
    )
    def test_module_failure(parser, filepath):
        with pytest.raises(SystemExit):
            parser.parse_args(['scan', '--filter', filepath])


def test_disable_filter(parser):
    with mock_named_temporary_file() as f:
        f.write(f'secret = "{uuid.uuid4()}"'.encode())

        # First, make sure that we actually catch it.
        f.seek(0)
        with transient_settings({
            'plugins_used': [{
                'name': 'KeywordDetector',
            }],
        }):
            secrets = SecretsCollection()
            secrets.scan_file(f.name)

            assert not secrets

        f.seek(0)
        with default_settings():
            parser.parse_args([
                'scan',
                '--disable-filter', 'detect_secrets.filters.heuristic.is_potential_uuid',

                # invalid filter
                '--disable-filter', 'blah',
            ])

            secrets = SecretsCollection()
            secrets.scan_file(f.name)

            assert secrets


@pytest.fixture
def parser():
    return ParserBuilder().add_console_use_arguments()
