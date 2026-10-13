import os
import re
from types import SimpleNamespace

import pytest

from detect_secrets.audit import io
from detect_secrets.util.code_snippet import get_code_snippet


@pytest.mark.parametrize(
    'config, expected',
    (
        (
            {
                'allow_labelling': True,
                'allow_backstep': True,
            },
            (
                'Should this string be committed to the repository? '
                '(y)es, (n)o, (s)kip, (b)ack, (q)uit: '
            ),
        ),
        (
            {
                'allow_labelling': False,
                'allow_backstep': True,
            },
            (
                'What would you like to do? '
                '(s)kip, (b)ack, (q)uit: '
            ),
        ),
    ),
)
def test_user_prompt(config, expected):
    prompter = io.UserPrompt(**config)
    assert str(prompter) == expected


def test_print_context_limits_long_lines_but_preserves_secret(monkeypatch):
    secret_value = 'SYNTHETIC_SECRET_12345'
    snippet = get_code_snippet(
        ['long unrelated line ' * 30, 'x' * 200 + secret_value + 'y' * 200],
        line_number=2,
        lines_of_context=1,
    )
    context = SimpleNamespace(
        snippet=snippet,
        secret=SimpleNamespace(secret_value=secret_value),
    )
    outputs = []
    monkeypatch.setattr(io, '_print_header', lambda _: None)
    monkeypatch.setattr(io, 'print_message', outputs.append)
    monkeypatch.setattr(
        io.shutil,
        'get_terminal_size',
        lambda fallback: os.terminal_size((80, 24)),
    )
    io.print_context(context)
    assert secret_value in outputs[0]
    # Line numbers and ANSI highlighting should not count as visible width.
    def plain(text):
        return re.sub(r'\x1b\[[0-9;]*m', '', text)
    assert len(plain(snippet.lines[0])) <= 70
    assert len(plain(snippet.target_line)) <= 70
