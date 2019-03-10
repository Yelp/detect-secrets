from __future__ import print_function
from __future__ import unicode_literals

import json
import os
import subprocess
import sys
from builtins import input
from collections import defaultdict

from ..plugins.common import initialize
from ..plugins.common.filetype import determine_file_type
from ..plugins.high_entropy_strings import HighEntropyStringsPlugin
from .baseline import merge_results
from .bidirectional_iterator import BidirectionalIterator
from .code_snippet import CodeSnippetHighlighter
from .color import AnsiColor
from .color import colorize
from .common import write_baseline_to_file
from .potential_secret import PotentialSecret


class SecretNotFoundOnSpecifiedLineError(Exception):
    def __init__(self, line):
        super(SecretNotFoundOnSpecifiedLineError, self).__init__(
            "ERROR: Secret not found on line {}!\n".format(line) +
            "Try recreating your baseline to fix this issue.",
        )


class RedundantComparisonError(Exception):
    pass


def audit_baseline(baseline_filename):
    original_baseline = _get_baseline_from_file(baseline_filename)
    if not original_baseline:
        return

    files_removed = _remove_nonexistent_files_from_baseline(original_baseline)

    all_secrets = list(_secret_generator(original_baseline))
    secrets_with_choices = [
        (filename, secret) for filename, secret in all_secrets
        if 'is_secret' not in secret
    ]
    total_choices = len(secrets_with_choices)
    secret_iterator = BidirectionalIterator(secrets_with_choices)

    current_secret_index = 0
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
    write_baseline_to_file(
        filename=baseline_filename,
        data=original_baseline,
    )


def compare_baselines(old_baseline_filename, new_baseline_filename):
    """
    This function enables developers to more easily configure plugin
    settings, by comparing two generated baselines and highlighting
    their differences.

    For effective use, a few assumptions are made:
        1. Baselines are sorted by (filename, line_number, hash).
           This allows for a deterministic order, when doing a side-by-side
           comparison.

        2. Baselines are generated for the same codebase snapshot.
           This means that we won't have cases where secrets are moved around;
           only added or removed.

    NOTE: We don't want to do a version check, because we want to be able to
    use this functionality across versions (to see how the new version fares
    compared to the old one).
    """
    if old_baseline_filename == new_baseline_filename:
        raise RedundantComparisonError

    old_baseline = _get_baseline_from_file(old_baseline_filename)
    new_baseline = _get_baseline_from_file(new_baseline_filename)

    _remove_nonexistent_files_from_baseline(old_baseline)
    _remove_nonexistent_files_from_baseline(new_baseline)

    # We aggregate the secrets first, so that we can display a total count.
    secrets_to_compare = _get_secrets_to_compare(old_baseline, new_baseline)
    total_reviews = len(secrets_to_compare)
    current_index = 0

    secret_iterator = BidirectionalIterator(secrets_to_compare)
    for filename, secret, is_removed in secret_iterator:
        _clear_screen()
        current_index += 1

        header = '{}      {}'
        if is_removed:
            plugins_used = old_baseline['plugins_used']
            header = header.format(
                colorize('Status:', AnsiColor.BOLD),
                '>> {} <<'.format(
                    colorize('REMOVED', AnsiColor.RED),
                ),
            )
        else:
            plugins_used = new_baseline['plugins_used']
            header = header.format(
                colorize('Status:', AnsiColor.BOLD),
                '>> {} <<'.format(
                    colorize('ADDED', AnsiColor.LIGHT_GREEN),
                ),
            )

        try:
            _print_context(
                filename,
                secret,
                current_index,
                total_reviews,
                plugins_used,
                additional_header_lines=header,
                force=is_removed,
            )
            decision = _get_user_decision(
                can_step_back=secret_iterator.can_step_back(),
                prompt_secret_decision=False,
            )
        except SecretNotFoundOnSpecifiedLineError:
            decision = _get_user_decision(prompt_secret_decision=False)

        if decision == 'q':
            print('Quitting...')
            break

        if decision == 'b':  # pragma: no cover
            current_index -= 2
            secret_iterator.step_back_on_next_iteration()


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


def _get_secrets_to_compare(old_baseline, new_baseline):
    """
    :rtype: list(tuple)
    :param: tuple is in the following format:
        filename: str; filename where identified secret is found
        secret: dict; PotentialSecret json representation
        is_secret_removed: bool; has the secret been removed from the
            new baseline?
    """
    def _check_string(a, b):
        if a == b:
            return 0
        if a < b:
            return -1
        return 1

    def _check_secret(a, b):
        if a == b:
            return 0

        if a['line_number'] < b['line_number']:
            return -1
        elif a['line_number'] > b['line_number']:
            return 1

        return _check_string(a['hashed_secret'], b['hashed_secret'])

    secrets_to_compare = []
    for old_filename, new_filename in _comparison_generator(
        sorted(old_baseline['results'].keys()),
        sorted(new_baseline['results'].keys()),
        compare_fn=_check_string,
    ):
        if not new_filename:
            secrets_to_compare += list(
                map(
                    lambda x: (old_filename, x, True,),
                    old_baseline['results'][old_filename],
                ),
            )
            continue
        elif not old_filename:
            secrets_to_compare += list(
                map(
                    lambda x: (new_filename, x, False,),
                    new_baseline['results'][new_filename],
                ),
            )
            continue

        for old_secret, new_secret in _comparison_generator(
            old_baseline['results'][old_filename],
            new_baseline['results'][new_filename],
            compare_fn=_check_secret,
        ):
            if old_secret == new_secret:
                # If they are the same, no point flagging it.
                continue

            if old_secret:
                secrets_to_compare.append(
                    (old_filename, old_secret, True,),
                )
            else:
                secrets_to_compare.append(
                    (new_filename, new_secret, False,),
                )

    return secrets_to_compare


def _comparison_generator(old_list, new_list, compare_fn):
    """
    :type old_list: sorted list
    :type new_list: sorted list

    :type compare_fn: function
    :param compare_fn:
        takes two arguments, A and B
        returns 0 if equal
        returns -1 if A is less than B
        else returns 1
    """
    old_index = 0
    new_index = 0
    while old_index < len(old_list) and new_index < len(new_list):
        old_value = old_list[old_index]
        new_value = new_list[new_index]

        status = compare_fn(old_value, new_value)
        if status == 0:
            yield (old_value, new_value,)
            old_index += 1
            new_index += 1
        elif status == -1:
            yield (old_value, None,)
            old_index += 1
        else:
            yield (None, new_value,)
            new_index += 1

    # Catch leftovers. Only one of these while statements should run.
    while old_index < len(old_list):
        yield (old_list[old_index], None,)
        old_index += 1
    while new_index < len(new_list):
        yield (None, new_list[new_index],)
        new_index += 1


def _clear_screen():  # pragma: no cover
    subprocess.call(['clear'])


def _print_context(  # pragma: no cover
    filename,
    secret,
    count,
    total,
    plugin_settings,
    additional_header_lines=None,
    force=False,
):
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

    :type additional_header_lines: str
    :param additional_header_lines: any additional lines to add to the
        header of the interactive audit display.

    :type force: bool
    :param force: if True, will print the lines of code even if it doesn't
        find the secret expected

    :raises: SecretNotFoundOnSpecifiedLineError
    """
    print('{} {} {} {}\n{} {}\n{} {}'.format(
        colorize('Secret:     ', AnsiColor.BOLD),
        colorize(str(count), AnsiColor.PURPLE),
        colorize('of', AnsiColor.BOLD),
        colorize(str(total), AnsiColor.PURPLE),
        colorize('Filename:   ', AnsiColor.BOLD),
        colorize(filename, AnsiColor.PURPLE),
        colorize('Secret Type:', AnsiColor.BOLD),
        colorize(secret['type'], AnsiColor.PURPLE),
    ))
    if additional_header_lines:
        print(additional_header_lines)

    print('-' * 10)

    error_obj = None
    try:
        secret_with_context = _get_secret_with_context(
            filename,
            secret,
            plugin_settings,
            force=force,
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
            user_input_string = 'Is this a valid secret? i.e. not a false-positive (y)es, (n)o, '
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


def _get_secret_with_context(
    filename,
    secret,
    plugin_settings,
    lines_of_context=5,
    force=False,
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

    :type force: bool
    :param force: if True, will print the lines of code even if it doesn't
        find the secret expected

    :raises: SecretNotFoundOnSpecifiedLineError
    """
    snippet = CodeSnippetHighlighter().get_code_snippet(
        filename,
        secret['line_number'],
        lines_of_context=lines_of_context,
    )

    try:
        raw_secret_value = get_raw_secret_value(
            snippet.target_line,
            secret,
            plugin_settings,
            filename,
        )

        snippet.highlight_line(raw_secret_value)
    except SecretNotFoundOnSpecifiedLineError:
        if not force:
            raise

        snippet.target_line = colorize(
            snippet.target_line,
            AnsiColor.BOLD,
        )

    return snippet.add_line_numbers()


def get_raw_secret_value(
    secret_line,
    secret,
    plugin_settings,
    filename,
):
    """
    :type secret_line: str
    :param secret_line: the line on which the secret is found

    :type secret: dict
    :param secret: see caller's docstring

    :type plugin_settings: list
    :param plugin_settings: see caller's docstring

    :type filename: str
    :param filename: this is needed, because PotentialSecret uses this
        as a means of comparing whether two secrets are equal.
    """
    plugin = initialize.from_secret_type(
        secret['type'],
        plugin_settings,
    )

    for raw_secret in raw_secret_generator(
        plugin,
        secret_line,
        filetype=determine_file_type(filename),
    ):
        secret_obj = PotentialSecret(
            plugin.secret_type,
            filename,
            secret=raw_secret,
        )

        # There could be more than two secrets on the same line.
        # We only want to highlight the right one.
        if secret_obj.secret_hash == secret['hashed_secret']:
            return raw_secret
    else:
        raise SecretNotFoundOnSpecifiedLineError(secret['line_number'])


def raw_secret_generator(plugin, secret_line, filetype):
    """Generates raw secrets by re-scanning the line, with the specified plugin

    :type plugin: BasePlugin
    :type secret_line: str
    :type filetype: FileType
    """
    for raw_secret in plugin.secret_generator(secret_line, filetype=filetype):
        yield raw_secret

    if issubclass(plugin.__class__, HighEntropyStringsPlugin):
        with plugin.non_quoted_string_regex(strict=False):
            for raw_secret in plugin.secret_generator(secret_line):
                yield raw_secret
