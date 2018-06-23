from enum import Enum


class Color(Enum):
    NORMAL = 0
    BOLD = 1

    RED = 2
    LIGHT_GREEN = 3
    PURPLE = 4


class _BashColor(object):

    PREFIX = '\033'

    def color(self, text, color):
        """
        :type text: str
        :param text: the text to colorize

        :type color: Color
        :param color: the color to make the text

        :returns: colored string
        """
        color_map = {
            Color.BOLD: '[1m',
            Color.RED: '[41m',
            Color.LIGHT_GREEN: '[92m',
            Color.PURPLE: '[95m',
        }

        return self.PREFIX + color_map[color] + text + \
            self.PREFIX + '[0m'


BashColor = _BashColor()
