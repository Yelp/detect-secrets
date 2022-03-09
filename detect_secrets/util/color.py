from enum import Enum
from os import getenv
from sys import stdout


def support_ansi_colors():
    return (getenv('CLICOLOR', '1') != '0' and stdout.isatty())\
        or getenv('CLICOLOR_FORCE', '0') != '0'


class AnsiColor(Enum):
    RESET = '[0m'
    BOLD = '[1m'
    RED = '[91m'
    RED_BACKGROUND = '[41m'
    LIGHT_GREEN = '[92m'
    PURPLE = '[95m'


def colorize(text: str, color: AnsiColor) -> str:
    if not support_ansi_colors():
        return text

    return '\x1b{}{}\x1b{}'.format(
        color.value,
        text,
        AnsiColor.RESET.value,
    )
