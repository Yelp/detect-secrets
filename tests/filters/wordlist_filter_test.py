import pytest

from detect_secrets import filters
from detect_secrets.settings import get_settings


@pytest.fixture(autouse=True)
def initialize_automaton():
    filters.wordlist.initialize('test_data/word_list.txt', min_length=8)

    yield

    filters.wordlist.get_automaton.cache_clear()


def test_success():
    # case-insensitivity
    assert filters.wordlist.should_exclude_secret('testPass') is True

    # min_length requirement
    assert filters.wordlist.should_exclude_secret('2short') is False

    assert get_settings().filters['detect_secrets.filters.wordlist.should_exclude_secret'] == {
        'min_length': 8,

        # Manually computed with `sha1sum test_data/word_list.txt`
        'file_hash': '116598304e5b33667e651025bcfed6b9a99484c7',
        'file_name': 'test_data/word_list.txt',
    }


def test_failure():
    # prefix match is not sufficient
    assert filters.wordlist.should_exclude_secret('AKIAnotr') is False
