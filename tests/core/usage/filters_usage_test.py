import tempfile

import pytest

from detect_secrets.constants import VerifiedResult
from detect_secrets.core import baseline
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.core.usage import ParserBuilder
from detect_secrets.settings import get_settings
from detect_secrets.settings import transient_settings


def test_no_verify_overrides_baseline_settings(parser):
    secrets = SecretsCollection()
    with tempfile.NamedTemporaryFile() as f, transient_settings({
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
    with tempfile.NamedTemporaryFile() as f, transient_settings({
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


@pytest.fixture
def parser():
    return ParserBuilder().add_console_use_arguments()
