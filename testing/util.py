import re
import shlex

import mock

from detect_secrets.core.usage import ParserBuilder
from detect_secrets.main import main
from detect_secrets.plugins.base import RegexBasedDetector
from detect_secrets.plugins.common.util import import_plugins


# https://stackoverflow.com/questions/14693701/how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python
_ansi_escape = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')


def uncolor(text):
    return _ansi_escape.sub('', text)


def get_regex_based_plugins():
    return {
        name: plugin
        for name, plugin in import_plugins(custom_plugin_paths=()).items()
        if issubclass(plugin, RegexBasedDetector)
    }


def parse_pre_commit_args_with_correct_prog(argument_string=''):
    parser = ParserBuilder()
    # Rename from pytest.py to what it is when ran
    parser.parser.prog = 'detect-secrets-hook'
    return parser.add_pre_commit_arguments()\
        .parse_args(argument_string.split())


def wrap_detect_secrets_main(command):
    with mock.patch(
        'detect_secrets.main.parse_args',
        return_value=_parse_console_use_args_with_correct_prog(command),
    ):
        return main(command.split())


def _parse_console_use_args_with_correct_prog(argument_string=''):
    parser = ParserBuilder()
    # Rename from pytest.py to what it is when ran
    parser.parser.prog = 'detect-secrets'
    return parser.add_console_use_arguments()\
        .parse_args(shlex.split(argument_string))
