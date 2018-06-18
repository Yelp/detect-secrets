#!/usr/bin/python
"""
 This is a collection of utility functions for easier, DRY testing.
"""
import io


def create_file_object_from_string(string):
    return io.StringIO(string)
