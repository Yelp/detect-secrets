import os

import pytest

from detect_secrets import filters
from detect_secrets.core.scan import scan_line
from detect_secrets.plugins.aws import AWSKeyDetector
from detect_secrets.settings import transient_settings


class TestIsSequentialString:
    @staticmethod
    @pytest.mark.parametrize(
        'secret',
        (
            # ASCII sequence
            'ABCDEF',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ',

            # Number sequences
            '0123456789',
            '1234567890',

            # Alphanumeric sequences
            'abcdefghijklmnopqrstuvwxyz0123456789',
            '0123456789abcdefghijklmnopqrstuvwxyz',

            # Hex sequences
            '0123456789abcdef',
            'abcdef0123456789',

            # Base64 sequences
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
            '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/',
        ),
    )
    def test_success(secret):
        assert filters.heuristic.is_sequential_string(secret)

    @staticmethod
    def test_failure():
        assert not filters.heuristic.is_sequential_string('BEEF1234')


@pytest.mark.parametrize(
    'secret',
    (
        '3636dd46-ea21-11e9-81b4-2a2ae2dbcce4',  # uuid1
        '97fb0431-46ac-41df-9ef9-1a18545ce2a0',  # uuid4
        'prefix-3636dd46-ea21-11e9-81b4-2a2ae2dbcce4-suffix',  # uuid in middle of string
    ),
)
def test_is_potential_uuid(secret):
    assert filters.heuristic.is_potential_uuid(secret)


class TestIsLikelyIdString:
    @pytest.mark.parametrize(
        'secret, line',
        [
            ('RANDOM_STRING', 'id: RANDOM_STRING'),
            ('RANDOM_STRING', 'id=RANDOM_STRING'),
            ('RANDOM_STRING', 'id = RANDOM_STRING'),
            ('RANDOM_STRING', 'myid: RANDOM_STRING'),
            ('RANDOM_STRING', 'myid=RANDOM_STRING'),
            ('RANDOM_STRING', 'myid = RANDOM_STRING'),
            ('RANDOM_STRING', 'userid: RANDOM_STRING'),
            ('RANDOM_STRING', 'userid=RANDOM_STRING'),
            ('RANDOM_STRING', 'userid = RANDOM_STRING'),
            ('RANDOM_STRING', 'data test_id: RANDOM_STRING'),
            ('RANDOM_STRING', 'data test_id=RANDOM_STRING'),
            ('RANDOM_STRING', 'data test_id = RANDOM_STRING'),
            ('RANDOM_STRING', 'ids = RANDOM_STRING, RANDOM_STRING'),
            ('RANDOM_STRING', 'my_ids: RANDOM_STRING, RANDOM_STRING'),
        ],
    )
    def test_success(self, secret, line):
        assert filters.heuristic.is_likely_id_string(secret, line)

    @pytest.mark.parametrize(
        'secret, line, plugin',
        [
            # the word hidden has the word id in it, but lets
            # not mark that as an id string
            ('RANDOM_STRING', 'hidden_secret: RANDOM_STRING', None),
            ('RANDOM_STRING', 'hidden_secret=RANDOM_STRING', None),
            ('RANDOM_STRING', 'hidden_secret = RANDOM_STRING', None),

            # fail silently if the secret isn't even on the line
            ('SOME_RANDOM_STRING', 'id: SOME_OTHER_RANDOM_STRING', None),

            # fail although the word david ends in id
            ('RANDOM_STRING', 'postgres://david:RANDOM_STRING', None),

            # fail since this is an aws access key id, a real secret
            ('AKIA4NACSIJMDDNSEDTE', 'aws_access_key_id=AKIA4NACSIJMDDNSEDTE', AWSKeyDetector()),
        ],
    )
    def test_failure(self, secret, line, plugin):
        assert not filters.heuristic.is_likely_id_string(secret, line, plugin)


@pytest.mark.parametrize(
    'line, result',
    (
        ('secret = {hunter2}', False),
        ('secret = <hunter2>', False),
        ('secret = "hunter2"', True),
        ('secret= ${hunter2}', False),
    ),
)
def test_is_templated_secret(line, result):
    with transient_settings({
        'plugins_used': [{
            'name': 'KeywordDetector',
        }],
        'filters_used': [{
            'path': 'detect_secrets.filters.heuristic.is_templated_secret',
        }],
    }):
        assert bool(list(scan_line(line))) is result


@pytest.mark.parametrize(
    'secret, result',
    (
        ('$secret', True),
        ('secret', False),
        ('', False),
    ),
)
def test_is_prefixed_with_dollar_sign(secret, result):
    assert filters.heuristic.is_prefixed_with_dollar_sign(secret) == result


@pytest.mark.parametrize(
    'line, result',
    (
        ('secret = get_secret_key()', True),
        ('secret = request.headers["apikey"]', True),
        ('secret = hunter2', False),
        ("<%= ENV['CLIENT_ACCESS_KEY_ID'].presence || 'AKIA123456789ABCDEF1' %>", True), # Erb template with intermediate method
        ("<%= ENV['CLIENT_ACCESS_KEY_ID'] || 'AKIA123456789ABCDEF1' %>", True),          # Erb template without intermediate method
        ("ENV['CLIENT_ACCESS_KEY_ID'].presence || 'AKIA123456789ABCDEF1'", True),        # Ruby with intermediate method
        ("ENV['CLIENT_ACCESS_KEY_ID'] || 'AKIA123456789ABCDEF1'", True),                 # Ruby without intermediate method
        ('not_a_secret ||= something_else', False),                                      # Ruby assignment
        ('not_a_secret || something_else', False),                                       # Ruby truthy validation
        ('api_key = ENV["API_KEY"].get() || "default_key"', True),                       # Ruby with intermediate method with assignment
        ('token = ENV["TOKEN"] || default_token', True),                                 # Ruby without intermediate method with assignment
        ('api_key ||= fetch_api_key()', True),                                           # Ruby without intermediate method with assignment
    ),
)
def test_is_indirect_reference(line, result):
    assert filters.heuristic.is_indirect_reference(line) is result


def test_is_lock_file():
    # Basic tests
    assert filters.heuristic.is_lock_file('composer.lock')
    assert filters.heuristic.is_lock_file('packages.lock.json')

    # file path
    assert filters.heuristic.is_lock_file('path/yarn.lock')

    # assert non-regex
    assert not filters.heuristic.is_lock_file('Gemfilealock')


@pytest.mark.parametrize(
    'secret, result',
    (
        ('*****', True),
        ('a&b23?!', False),
    ),
)
def test_is_not_alphanumeric_string(secret, result):
    assert filters.heuristic.is_not_alphanumeric_string(secret) is result


@pytest.mark.parametrize(
    'filename, result',
    (
        ('{sep}path{sep}swagger-ui.html', True),
        ('{sep}path{sep}swagger{sep}config.yml', True),
        ('{sep}path{sep}non{sep}swager{sep}files', False),
    ),
)
def test_is_swagger_file(filename, result):
    assert filters.heuristic.is_swagger_file(filename.format(sep=os.path.sep)) is result
