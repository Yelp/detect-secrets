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
                'Is this a secret that should be committed to this repository? '
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
