from __future__ import print_function

import json
import subprocess
import sys
from builtins import input
from collections import defaultdict

from .baseline import merge_results
from .color import BashColor
from .color import Color


def audit_baseline(baseline_filename):
    original_baseline = _get_baseline_from_file(baseline_filename)
    if not original_baseline:
        return

    has_scanned_one_secret = False
    results = defaultdict(list)
    for filename, secret, index, total in _secret_generator(original_baseline):
        has_scanned_one_secret = True
        _clear_screen()
        _print_context(filename, secret, index, total)

        decision = _get_user_decision()
        if decision == 'q':
            print('Quitting...')
            break

        _handle_user_decision(decision, secret)
        results[filename].append(secret)

    if not has_scanned_one_secret:
        print('Nothing to audit!')
        return

    print('Saving progress...')
    original_baseline['results'] = merge_results(
        original_baseline['results'],
        dict(results),
    )
    _save_baseline_to_file(baseline_filename, original_baseline)


def _clear_screen():    # pragma: no cover
    subprocess.call(['clear'])


def _print_context(filename, secret, count, total):   # pragma: no cover
    """
    :type filename: str
    :param filename: the file currently scanned.

    :type secret: dict, in PotentialSecret.json() format
    :param secret: the secret, represented in the baseline file.

    :type count: int
    :param count: current count of secrets scanned so far

    :type total: int
    :param total: total number of secrets in baseline
    """
    secrets_left = '[{}/{}]'.format(
        count,
        total,
    )
    print('{} {} {}'.format(
        BashColor.color(
            'Filename:',
            Color.BOLD,
        ),
        BashColor.color(
            filename,
            Color.PURPLE,
        ),
        BashColor.color(
            secrets_left,
            Color.BOLD,
        ),
    ))
    print('-' * 10)
    print(_get_secret_with_context(
        filename,
        secret['line_number'],
        5,
    ))
    print('-' * 10)


def _handle_user_decision(decision, secret):
    if decision == 'y':
        secret['is_secret'] = True
    elif decision == 'n':
        secret['is_secret'] = False


def _get_baseline_from_file(filename):  # pragma: no cover
    try:
        with open(filename) as f:
            return json.loads(f.read())
    except (IOError, json.decoder.JSONDecodeError):
        print('Not a valid baseline file!', file=sys.stderr)
        return


def _save_baseline_to_file(filename, data):
    with open(filename, 'w') as f:
        f.write(json.dumps(
            data,
            indent=2,
            sort_keys=True,
        ))


def _secret_generator(baseline):
    current_secret_index = 1
    num_secrets_to_parse = sum(map(
        lambda filename: len(list(filter(
            lambda secret: not hasattr(secret, 'is_secret'),
            baseline['results'][filename],
        ))),
        baseline['results'],
    ))

    for filename, secrets in baseline['results'].items():
        for secret in secrets:
            try:
                secret['is_secret']
            except KeyError:
                yield filename, secret, current_secret_index, num_secrets_to_parse

            current_secret_index += 1

        break


def _get_secret_with_context(filename, secret_lineno, lines_of_context):
    """
    Displays the secret, with surrounding lines of code for better context.

    :type filename: str
    :param filename: filename where secret resides in

    :type secret_lineno: int
    :param secret_lineno: line where secret is found

    :type lines_of_context: int
    :param lines_of_context: number of lines displayed before and after
        secret.
    """
    start_line = 1 if secret_lineno <= lines_of_context \
        else secret_lineno - lines_of_context
    end_line = secret_lineno + lines_of_context

    output = subprocess.check_output([
        'sed',
        '-n', '{},{}p'.format(start_line, end_line),
        filename,
    ]).decode('utf-8')

    # TODO: Highlight the secret found.

    return '\n'.join(
        map(
            lambda x: '{}:{}'.format(
                BashColor.color(
                    str(int(x[0]) + start_line),
                    Color.LIGHT_GREEN,
                ),
                x[1],
            ),
            enumerate(output.splitlines()),
        ),
    )


def _get_user_decision():
    user_input = None
    while user_input not in ['y', 'n', 's', 'q']:
        if user_input:
            print('Invalid input.')

        user_input = input('Is this a valid secret? (y)es, (n)o, (s)kip, (q)uit: ')
        if user_input:
            user_input = user_input[0].lower()

    return user_input
