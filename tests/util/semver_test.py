import pytest

from detect_secrets.util.semver import Version


def test_init():
    version = Version('1.2.3')
    assert version.major == 1
    assert version.minor == 2
    assert version.patch == 3


@pytest.mark.parametrize(
    'a, b, expected',
    (
        ('0.0.0', '0.0.0', False),
        ('0.0.0', '0.0.1', True),
        ('0.1.0', '0.0.1', False),
        ('1.0.0', '0.0.1', False),
        ('0.0.10', '0.1.0', True),
    ),
)
def test_less_than(a, b, expected):
    assert (Version(a) < Version(b)) is expected


def test_equal():
    assert Version('0.1.2') == Version('0.1.2')
