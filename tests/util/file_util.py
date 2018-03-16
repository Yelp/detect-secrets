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
