#!/usr/bin/python
"""
 This is a collection of utility functions for easier, DRY testing.
"""
import sys

if sys.version_info[0] == 2:    # pragma: no cover
    import cStringIO as io
else:   # pragma: no cover
    import io


def create_file_object_from_string(string):
    return io.StringIO(string)


def create_file_object_that_throws_unicode_decode_error(string):

    class BadUnicodeFile(object):
        """For Python 2 compatibility, we can't extend io.StringIO, then override the __next__
        function. So we need to do this hackish way."""

        def __init__(self, string):
            self.obj = io.StringIO(string)

        def __iter__(self):
            return self

        def __next__(self):
            raise UnicodeDecodeError('encoding type', b'subject', 0, 1, 'exception message')

        if sys.version_info[0] == 2:    # pragma: no cover
            def next(self):
                return self.__next__()

    return BadUnicodeFile(string)
