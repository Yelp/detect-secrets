from sys import stdout

from detect_secrets.util.color import AnsiColor
from detect_secrets.util.color import colorize


def colorize_enabled(text: str, color: AnsiColor) -> str:
    return '\x1b{}{}\x1b{}'.format(
        color.value,
        text,
        AnsiColor.RESET.value,
    )


def expect_enabled(text: str):
    for color in AnsiColor:
        expected = colorize_enabled(text, color)
        assert colorize(text, color) == expected


def expect_disabled(text: str):
    for color in AnsiColor:
        assert colorize(text, color) == text


def test_colorize_enabled_terminal_disabled_piped(monkeypatch):
    monkeypatch.setenv('CLICOLOR', '1')

    if stdout.isatty():
        expect_enabled('abc')
    else:
        expect_disabled('abc')


def test_colorize_enabled_force(monkeypatch):
    monkeypatch.setenv('CLICOLOR_FORCE', '1')

    expect_enabled('abc')


def test_colorize_disabled(monkeypatch):
    monkeypatch.setenv('CLICOLOR', '0')

    expect_disabled('abc')
