import pytest

from detect_secrets.core.usage import ParserBuilder


@pytest.fixture
def parser():
    return ParserBuilder().add_console_use_arguments()


def test_normal_mode_requires_single_file(parser):
    with pytest.raises(SystemExit):
        parser.parse_args(['audit', 'fileA', 'fileB'])


@pytest.mark.skip(reason='TODO')
def test_normal_mode_success(parser):
    args = parser.parse_args(['audit', 'fileA'])    # noqa: F841
    # TODO: What is `audit` expecting?


def test_diff_mode_requires_two_files(parser):
    with pytest.raises(SystemExit):
        parser.parse_args(['audit', 'fileA', '--diff'])


@pytest.mark.skip(reason='TODO')
def test_diff_mode_success(parser):
    args = parser.parse_args(['audit', 'fileA', 'fileB', '--diff'])     # noqa: F841
    # TODO: What is `audit` expecting?


def test_diff_mode_fails_with_stats(parser):
    with pytest.raises(SystemExit):
        parser.parse_args(['audit', 'fileA', 'fileB', '--diff', '--stats'])
