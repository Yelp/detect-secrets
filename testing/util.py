import re

from detect_secrets.plugins.base import RegexBasedDetector
from detect_secrets.plugins.common.util import import_plugins


# https://stackoverflow.com/questions/14693701/how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python
_ansi_escape = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')


def uncolor(text):
    return _ansi_escape.sub('', text)


def get_regex_based_plugins():
    return {
        name: plugin
        for name, plugin in import_plugins().items()
        if issubclass(plugin, RegexBasedDetector)
    }
