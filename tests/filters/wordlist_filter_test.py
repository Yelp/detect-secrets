from pathlib import Path

import pytest

from detect_secrets import filters
from detect_secrets.filters.util import compute_file_hash
from detect_secrets.settings import get_settings
from detect_secrets.settings import transient_settings


class TestShouldExcludeSecret:
    @staticmethod
    @pytest.fixture(autouse=True)
    def initialize_automaton():
        filters.wordlist.initialize('test_data/word_list.txt', min_length=8)

        yield

        filters.wordlist.get_automaton.cache_clear()

    @staticmethod
    def test_success():
        # Compute file_hash manually due to file path operating system differences
        file_hash = compute_file_hash(Path('test_data/word_list.txt'))

        # case-insensitivity
        assert filters.wordlist.should_exclude_secret('testPass') is True

        # min_length requirement
        assert filters.wordlist.should_exclude_secret('2short') is False

        assert get_settings().filters['detect_secrets.filters.wordlist.should_exclude_secret'] == {
            'min_length': 8,
            'file_hash': file_hash,
            'file_name': 'test_data/word_list.txt',
        }

    @staticmethod
    def test_failure():
        # prefix match is not sufficient
        assert filters.wordlist.should_exclude_secret('AKIAnotr') is False


def test_empty_wordlist_does_not_crash(tmp_path):
    # Regression test for https://github.com/Yelp/detect-secrets/issues/844:
    # an empty (or all-too-short) word list never adds any words to the
    # automaton, so make_automaton() leaves it in TRIE mode and a plain
    # call to should_exclude_secret used to raise AttributeError instead
    # of returning False.
    empty_word_list = tmp_path / 'empty_word_list.txt'
    empty_word_list.write_text('')

    filters.wordlist.initialize(str(empty_word_list), min_length=3)
    try:
        assert filters.wordlist.should_exclude_secret('APEOptState') is False
    finally:
        filters.wordlist.get_automaton.cache_clear()


def test_load_from_baseline():
    with transient_settings({
        'filters_used': [{
            'path': 'detect_secrets.filters.wordlist.should_exclude_secret',
            'min_length': 8,
            'file_name': 'test_data/word_list.txt',
            'file_hash': '116598304e5b33667e651025bcfed6b9a99484c7',
        }],
    }):
        assert filters.wordlist.should_exclude_secret('testPass') is True
