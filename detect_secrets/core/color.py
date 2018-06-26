from enum import Enum


class Color(Enum):
    NORMAL = '[0m'
    BOLD = '[1m'

    RED = '[41m'
    LIGHT_GREEN = '[92m'
    PURPLE = '[95m'


class _BashColor(object):

    PREFIX = '\033'

    def __init__(self):
        self.DISABLED = False

    def enable_color(self):
        self.DISABLED = False

    def disable_color(self):
        self.DISABLED = True

    def color(self, text, color):
        """
        :type text: str
        :param text: the text to colorize

        :type color: Color
        :param color: the color to make the text

        :returns: colored string
        """
        if self.DISABLED:
            return text

        return self.PREFIX + color.value + text + \
            self.PREFIX + Color.NORMAL.value


BashColor = _BashColor()
