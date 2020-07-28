"""This is a collection of utility functions for easier, DRY testing."""
import io
from collections import defaultdict
from collections import namedtuple
from contextlib import contextmanager
from subprocess import CalledProcessError

import mock


@contextmanager
def mock_git_calls(subprocess_namespace, cases):
    """We perform several subprocess.check_output calls for git commands,
    but we only want to mock one at a time. This function helps us do that.

    However, the idea is that we *never* want to call out to git in tests,
    so we should mock out everything that does that.

    :type cases: iterable(SubprocessMock)
    :type subprocess_namespace: str
    :param subprocess_namespace: should be the namespace referring to check_output.
        E.g. `detect_secrets.pre_commit_hook.subprocess.check_output`
    """
    # We need to use a dictionary, because python2.7 does not support
    # the `nonlocal` keyword (and needs to share scope with
    # _mock_single_git_call function)
    current_case = {'index': 0}

    def _mock_subprocess_git_call(cmds, **kwargs):
        command = ' '.join(cmds)

        try:
            case = cases[current_case['index']]
        except IndexError:  # pragma: no cover
            raise AssertionError(
                '\nExpected: ""\n'
                'Actual: "{}"'.format(
                    command,
                ),
            )
        current_case['index'] += 1

        if command != case.expected_input:  # pragma: no cover
            # Pretty it up a little, for display
            if not case.expected_input.startswith('git'):
                case.expected_input = 'git ' + case.expected_input

            raise AssertionError(
                '\nExpected: "{}"\n'
                'Actual: "{}"'.format(
                    case.expected_input,
                    command,
                ),
            )

        if case.should_throw_exception:
            raise CalledProcessError(1, '', case.mocked_output)

        return case.mocked_output

    with mock.patch(
            subprocess_namespace,
            side_effect=_mock_subprocess_git_call,
    ):
        yield


class SubprocessMock(
    namedtuple(
        'SubprocessMock',
        [
            'expected_input',
            'mocked_output',
            'should_throw_exception',
        ],
    ),
):
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
            should_throw_exception,
        )


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
    """We heavily rely on file.seek(0), and until we can change this, we need
    to do a bit more overhead mocking, since the library doesn't support it.

    https://github.com/testing-cabal/mock/issues/426
    """
    m = mock.mock_open(read_data=data)
    with mock.patch(namespace, m):
        # This is the patch that we do, because it seems that that the
        # side_effect resets the data (exactly what we want with our use
        # case of seek).
        m().seek = m.side_effect

        yield m


def mock_file_object(string):
    return io.StringIO(string)


@contextmanager
def mock_printer(obj):
    """
    :type obj: module
    """
    class PrinterShim:
        def __init__(self):
            self.clear()

        def add(self, message, *args, **kwargs):
            self.message += str(message) + '\n'

        def clear(self):
            self.message = ''

    shim = PrinterShim()
    with mock.patch.object(obj, 'print', shim.add):
        yield shim


@contextmanager
def mock_log(namespace):
    class MockLogWrapper:
        """This is used to check what is being logged."""

        def __init__(self):
            self.messages = defaultdict(str)

        def error(self, message, *args):
            self.messages['error'] += (str(message) + '\n') % args

        @property
        def error_messages(self):
            return self.messages['error']

        def warning(self, message, *args):
            self.messages['warning'] += (str(message) + '\n') % args

        @property
        def warning_messages(self):
            return self.messages['warning']

        def info(self, message, *args):
            self.messages['info'] += (str(message) + '\n') % args

        @property
        def info_messages(self):
            return self.messages['info']

    wrapper = MockLogWrapper()
    with mock.patch(namespace, wrapper):
        yield wrapper
