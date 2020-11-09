import pytest

from detect_secrets.core.usage import ParserBuilder


@pytest.fixture
def parser():
    return ParserBuilder().add_console_use_arguments()


def test_normal_mode_requires_single_file(parser):
    with pytest.raises(SystemExit):
        parser.parse_args(['audit', 'fileA', 'fileB'])


def test_diff_mode_requires_two_files(parser):
    with pytest.raises(SystemExit):
        parser.parse_args(['audit', 'fileA', '--diff'])
