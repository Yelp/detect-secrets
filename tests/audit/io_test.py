import pytest

from detect_secrets.audit import io


@pytest.mark.parametrize(
    'config, expected',
    (
        (
            {
                'allow_labelling': True,
                'allow_backstep': True,
            },
            (
                'Is this a valid secret (not a false-positive)? '
                '(y)es, (n)o, (s)kip, (b)ack, (q)uit'
            ),
        ),
        (
            {
                'allow_labelling': False,
                'allow_backstep': True,
            },
            (
                'What would you like to do? '
                '(s)kip, (b)ack, (q)uit'
            ),
        ),
    ),
)
def test_user_prompt(config, expected):
    prompter = io.UserPrompt(**config)
    assert str(prompter) == expected
