import re

# https://stackoverflow.com/questions/14693701/how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python
_ansi_escape = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')


def uncolor(text):
    return _ansi_escape.sub('', text)
