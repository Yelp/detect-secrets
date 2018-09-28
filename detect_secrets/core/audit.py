from __future__ import print_function

import json
import os
import subprocess
import sys
import textwrap
from builtins import input
from collections import defaultdict

from ..plugins.core import initialize
from ..plugins.high_entropy_strings import HighEntropyStringsPlugin
from .baseline import merge_results
from .bidirectional_iterator import BidirectionalIterator
from .color import BashColor
from .color import Color
from .potential_secret import PotentialSecret


class SecretNotFoundOnSpecifiedLineError(Exception):
    pass


def audit_baseline(baseline_filename):
    original_baseline = _get_baseline_from_file(baseline_filename)
    if not original_baseline:
        return

    files_removed = _remove_nonexistent_files_from_baseline(original_baseline)

    current_secret_index = 0
    all_secrets = list(_secret_generator(original_baseline))
    secrets_with_choices = [
        (filename, secret) for filename, secret in all_secrets
        if 'is_secret' not in secret
    ]
    total_choices = len(secrets_with_choices)
    secret_iterator = BidirectionalIterator(secrets_with_choices)

    for filename, secret in secret_iterator:
        _clear_screen()

        current_secret_index += 1

        try:
            _print_context(
                filename,
                secret,
                current_secret_index,
                total_choices,
                original_baseline['plugins_used'],
            )
            decision = _get_user_decision(can_step_back=secret_iterator.can_step_back())
        except SecretNotFoundOnSpecifiedLineError:
            decision = _get_user_decision(prompt_secret_decision=False)

        if decision == 'q':
            print('Quitting...')
            break

        if decision == 'b':
            current_secret_index -= 2
            secret_iterator.step_back_on_next_iteration()

        _handle_user_decision(decision, secret)

    if current_secret_index == 0 and not files_removed:
        print('Nothing to audit!')
        return

    print('Saving progress...')
    results = defaultdict(list)
    for filename, secret in all_secrets:
        results[filename].append(secret)

    original_baseline['results'] = merge_results(
        original_baseline['results'],
        dict(results),
    )
    _save_baseline_to_file(baseline_filename, original_baseline)


def _get_baseline_from_file(filename):  # pragma: no cover
    try:
        with open(filename) as f:
            return json.loads(f.read())
    except (IOError, json.decoder.JSONDecodeError):
        print('Not a valid baseline file!', file=sys.stderr)
        return


def _remove_nonexistent_files_from_baseline(baseline):
    files_removed = False
    for filename in baseline['results'].copy():
        if not os.path.exists(filename):
            del baseline['results'][filename]
            files_removed = True
    return files_removed


def _secret_generator(baseline):
    """Generates secrets to audit, from the baseline"""
    for filename, secrets in baseline['results'].items():
        for secret in secrets:
            yield filename, secret


def _clear_screen():    # pragma: no cover
    subprocess.call(['clear'])


def _print_context(filename, secret, count, total, plugin_settings):   # pragma: no cover
    """
    :type filename: str
    :param filename: the file currently scanned.

    :type secret: dict, in PotentialSecret.json() format
    :param secret: the secret, represented in the baseline file.

    :type count: int
    :param count: current count of secrets scanned so far

    :type total: int
    :param total: total number of secrets in baseline

    :type plugin_settings: list
    :param plugin_settings: plugins used to create baseline.

    :raises: SecretNotFoundOnSpecifiedLineError
    """
    secrets_left = '{}/{}'.format(
        count,
        total,
    )
    print('{} {}\n{} {}'.format(
        BashColor.color(
            'Secrets Left:',
            Color.BOLD,
        ),
        BashColor.color(
            secrets_left,
            Color.PURPLE,
        ),
        BashColor.color(
            'Filename:    ',
            Color.BOLD,
        ),
        BashColor.color(
            filename,
            Color.PURPLE,
        ),
    ))
    print('-' * 10)

    error_obj = None
    try:
        secret_with_context = _get_secret_with_context(
            filename,
            secret,
            plugin_settings,
        )
        print(secret_with_context)
    except SecretNotFoundOnSpecifiedLineError as e:
        error_obj = e
        print(e)

    print('-' * 10)

    if error_obj:
        raise error_obj


def _get_user_decision(prompt_secret_decision=True, can_step_back=False):
    """
    :type prompt_secret_decision: bool
    :param prompt_secret_decision: if False, won't ask to label secret.
    """
    allowable_user_input = ['s', 'q']
    if prompt_secret_decision:
        allowable_user_input.extend(['y', 'n'])
    if can_step_back:
        allowable_user_input.append('b')

    user_input = None
    while user_input not in allowable_user_input:
        if user_input:
            print('Invalid input.')

        if 'y' in allowable_user_input:
            user_input_string = 'Is this a valid secret? (y)es, (n)o, '
        else:
            user_input_string = 'What would you like to do? '
        if 'b' in allowable_user_input:
            user_input_string += '(b)ack, '
        user_input_string += '(s)kip, (q)uit: '

        user_input = input(user_input_string)
        if user_input:
            user_input = user_input[0].lower()

    return user_input


def _handle_user_decision(decision, secret):
    if decision == 'y':
        secret['is_secret'] = True
    elif decision == 'n':
        secret['is_secret'] = False
    elif decision == 's' and 'is_secret' in secret:
        del secret['is_secret']


def _save_baseline_to_file(filename, data):  # pragma: no cover
    with open(filename, 'w') as f:
        f.write(json.dumps(
            data,
            indent=2,
            sort_keys=True,
            separators=(',', ': '),
        ))


def _get_secret_with_context(
    filename,
    secret,
    plugin_settings,
    lines_of_context=5,
):
    """
    Displays the secret, with surrounding lines of code for better context.

    :type filename: str
    :param filename: filename where secret resides in

    :type secret: dict, PotentialSecret.json() format
    :param secret: the secret listed in baseline

    :type plugin_settings: list
    :param plugin_settings: plugins used to create baseline.

    :type lines_of_context: int
    :param lines_of_context: number of lines displayed before and after
        secret.

    :raises: SecretNotFoundOnSpecifiedLineError
    """
    secret_lineno = secret['line_number']
    start_line = 1 if secret_lineno <= lines_of_context \
        else secret_lineno - lines_of_context
    end_line = secret_lineno + lines_of_context

    output = subprocess.check_output([
        'sed',
        '-n', '{},{}p'.format(start_line, end_line),
        filename,
    ]).decode('utf-8').splitlines()

    trailing_lines_of_context = lines_of_context
    if len(output) < end_line - start_line + 1:
        # This handles the case of a short file.
        num_lines_in_file = int(subprocess.check_output([
            'wc',
            '-l',
            filename,
        ]).decode('utf-8').split()[0])

        trailing_lines_of_context = lines_of_context - \
            (end_line - num_lines_in_file)

    # -1, because that's where the secret actually is (without it,
    # it would just be the start of the context block).
    # NOTE: index_of_secret_in_output should *always* be negative.
    index_of_secret_in_output = -trailing_lines_of_context - 1

    output[index_of_secret_in_output] = _highlight_secret(
        output[index_of_secret_in_output],
        secret,
        filename,
        plugin_settings,
    )

    # Adding line numbers
    return '\n'.join(
        map(
            lambda x: '{}:{}'.format(
                BashColor.color(
                    str(int(x[0]) + start_line),
                    Color.LIGHT_GREEN,
                ),
                x[1],
            ),
            enumerate(output),
        ),
    )


def _highlight_secret(secret_line, secret, filename, plugin_settings):
    """
    :type secret_line: str
    :param secret_line: the line on whcih the secret is found

    :type secret: dict
    :param secret: see caller's docstring

    :type filename: str
    :param filename: this is needed, because PotentialSecret uses this
        as a means of comparing whether two secrets are equal.

    :type plugin_settings: list
    :param plugin_settings: see caller's docstring

    :rtype: str
    :returns: secret_line, but with the actual secret highlighted.
    """
    plugin = initialize.from_secret_type(
        secret['type'],
        plugin_settings,
    )

    for raw_secret in _raw_secret_generator(plugin, secret_line):
        secret_obj = PotentialSecret(
            plugin.secret_type,
            filename,
            secret=raw_secret,
        )

        # There could be more than two secrets on the same line.
        # We only want to highlight the right one.
        if secret_obj.secret_hash == secret['hashed_secret']:
            break
    else:
        raise SecretNotFoundOnSpecifiedLineError(
            textwrap.dedent("""
                ERROR: Secret not found on specified line number!
                Try recreating your baseline to fix this issue.
            """)[1:-1],
        )

    index_of_secret = secret_line.index(raw_secret)
    return '{}{}{}'.format(
        secret_line[:index_of_secret],
        BashColor.color(
            raw_secret,
            Color.RED,
        ),
        secret_line[index_of_secret + len(raw_secret):],
    )


def _raw_secret_generator(plugin, secret_line):
    """Generates raw secrets by re-scanning the line, with the specified plugin"""
    for raw_secret in plugin.secret_generator(secret_line):
        yield raw_secret

    if issubclass(plugin.__class__, HighEntropyStringsPlugin):
        with plugin.non_quoted_string_regex(strict=False):
            for raw_secret in plugin.secret_generator(secret_line):
                yield raw_secret
