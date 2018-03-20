"""
 This is a collection of utility functions for easier, DRY testing.
"""
from collections import namedtuple
from contextlib import contextmanager
from subprocess import CalledProcessError

import mock


def mock_subprocess(case_tuple):
    """We perform several subprocess.check_output calls, but we want to only mock
    one of them at a time. This function helps us do that.

    :type case_tuple: tuple of SubprocessMock
    :param case_tuple: See docstring for SubprocessMock
    """
    def fn(inputs, **kwargs):
        while len(inputs) >= 2 and inputs[1] in ['--git-dir', '--work-tree']:
            # Remove `--git-dir <arg>` from git command.
            # This is just a convenience / increased readability conditional
            inputs = inputs[0:1] + inputs[3:]

        str_input = ' '.join(
            map(lambda x: x.decode('utf-8')
                if not isinstance(x, str) else x, inputs)
        )
        for tup in case_tuple:
            if not str_input.startswith(tup.expected_input):
                # We don't care what is returned, if we're not mocking it.
                continue

            if tup.should_throw_exception:
                raise CalledProcessError(1, '', tup.mocked_output)

            return tup.mocked_output

        # Default return value is just a byte-string.
        return b''

    return fn


class SubprocessMock(namedtuple(
    'SubprocessMock',
    [
        'expected_input',
        'mocked_output',
        'should_throw_exception',
    ]
)):
    """For use with mock_subprocess.

    :type expected_input: string
    :param expected_input: only return mocked_output if input matches this

    :type mocked_output: mixed
    :param mocked_output: value you want to return, when expected_input matches.

    :type should_throw_exception: bool
    :param should_throw_exception: if True, will throw subprocess.CalledProcessError with
                                   mocked output as error message
    """
    def __new__(cls, expected_input, mocked_output, should_throw_exception=False):
        return super(SubprocessMock, cls).__new__(
            cls,
            expected_input,
            mocked_output,
            should_throw_exception
        )


class PropertyMock(mock.Mock):
    """Allows the mocking of class functions with the @property decorator"""

    def __get__(self, instance, owner):
        return self()


def setup_global_mocks(obj, mocks=[]):  # pragma: no cover
    """
    Mocks out global objects, for general test cases.
    :param obj:   unittest.TestCase
    :param mocks: mixed; either modules_to_mock_out :string, or
                  (modules_to_mock_out :string, autospec :boolean)
    """
    for item in mocks:
        autospec = True
        if not isinstance(item, str) and len(item) > 1:
            autospec = item[1]
            item = item[0]

        m = mock.patch(item, autospec=autospec)

        obj.addCleanup(m.stop)
        m.start()


def Any(cls):
    """Used to call assert_called_with with any argument.

    Usage: Any(list) => allows any list to pass as input
    """
    class Any(cls):
        def __eq__(self, other):
            return isinstance(other, cls)
    return Any()


@contextmanager
def mock_open(data, namespace):
    m = mock.mock_open(read_data=data)
    with mock.patch(namespace, m):
        yield m


@contextmanager
def mock_log(namespace):
    with mock.patch(namespace, autospec=True) as m:
        yield m
