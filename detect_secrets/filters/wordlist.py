"""
There may be known words that are definitely test keys (e.g. AKIATEST for AWS keys).
One way that we can filter these out is by passing in a list of words that we know
will result in false positives. This filter efficiently processes this through the
use of the Aho-Corasick algorithm.
"""
import hashlib
from functools import lru_cache
from typing import Any

from ..settings import get_settings


Automaton = Any


def is_feature_enabled() -> bool:
    try:
        get_automaton()
        return True
    except ImportError:
        return False


def initialize(wordlist_filename: str, min_length: int = 3, file_hash: str = '') -> Automaton:
    """
    :param min_length: if words are too small, the automaton will flag too many
        words. As a result, our recall will decrease without a precision boost.
        Tweak this value to customize it based on your own findings.

    :param file_hash: this is currently used for baseline reporting purposes only, rather than
        engine's functionality. One can imagine a future where this automaton model is
        cached and keyed off the hash, and thus, this file_hash can be used to see if the
        cache needs to be invalidated.

        But alas, this functionality has yet to be implemented.
    """
    # See https://pyahocorasick.readthedocs.io/en/latest/ for more information.
    automaton = get_automaton()
    with open(wordlist_filename) as f:
        for line in f.readlines():
            line = line.lower().strip()

            if len(line) < min_length:
                continue

            automaton.add_word(line, line)

    path = f'{__name__}.should_exclude_secret'
    get_settings().filters[path] = {
        'min_length': min_length,
        'file_name': wordlist_filename,
        'file_hash': _compute_wordlist_hash(wordlist_filename),
    }

    automaton.make_automaton()
    return automaton


def should_exclude_secret(secret: str) -> bool:
    try:
        # .lower() to make everything case-insensitive
        next(get_automaton().iter(string=secret.lower()))
        return True
    except StopIteration:
        return False


@lru_cache(maxsize=1)
def get_automaton() -> Automaton:
    import ahocorasick
    return ahocorasick.Automaton()


def _compute_wordlist_hash(filename: str, buffer_size: int = 64 * 1024) -> str:
    """
    We compute the hash based on the file contents, rather than the filename itself, since we
    want to know if the underlying contents of the file changes.

    This is akin to:
        $ sha1sum <filename>
    """
    sha1 = hashlib.sha1()
    with open(filename, 'rb') as f:
        data = f.read(buffer_size)
        while data:
            sha1.update(data)
            data = f.read(buffer_size)

    return sha1.hexdigest()
