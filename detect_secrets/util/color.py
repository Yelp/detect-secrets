from enum import Enum


class AnsiColor(Enum):
    RESET = '[0m'
    BOLD = '[1m'
    RED = '[91m'
    RED_BACKGROUND = '[41m'
    LIGHT_GREEN = '[92m'
    PURPLE = '[95m'


def colorize(text, color):
    return '\x1b{}{}\x1b{}'.format(
        color.value,
        text,
        AnsiColor.RESET.value,
    )
