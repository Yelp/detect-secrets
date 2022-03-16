import json
from typing import List

import tabulate

from detect_secrets.core import audit
from detect_secrets.core.color import AnsiColor
from detect_secrets.core.color import colorize


def get_stats(
    live_secrets: List,
    unaudited_secrets: List,
    audited_real_secrets: List,
    baseline_filename: str,
    fail_on_live: bool,
    fail_on_unaudited: bool,
    fail_on_audited_real: bool,
):
    """
    Returns a dictionary containing aggregate stats, to be used in a report.
    """
    secrets = audit.get_secrets_list_from_file(baseline_filename)

    stats = {'reviewed': len(secrets)}

    if fail_on_live:
        stats['live'] = len(live_secrets)

    if fail_on_unaudited:
        stats['unaudited'] = len(unaudited_secrets)

    if fail_on_audited_real:
        stats['audited_real'] = len(audited_real_secrets)

    return stats


def print_json_report(
    live_secrets: List,
    unaudited_secrets: List,
    audited_real_secrets: List,
    baseline_filename: str,
    fail_on_live: bool,
    fail_on_unaudited: bool,
    fail_on_audited_real: bool,
) -> None:
    """
    Prints a JSON report summarizing information about secrets
    which failed certain conditions.
    """
    stats = get_stats(
        live_secrets,
        unaudited_secrets,
        audited_real_secrets,
        baseline_filename,
        fail_on_live,
        fail_on_unaudited,
        fail_on_audited_real,
    )

    secrets = []

    if fail_on_live:
        secrets += live_secrets

    if fail_on_unaudited:
        secrets += unaudited_secrets

    if fail_on_audited_real:
        secrets += audited_real_secrets

    print(json.dumps({'stats': stats, 'secrets': secrets}, indent=4))


def print_table_report(
    live_secrets: List,
    unaudited_secrets: List,
    audited_real_secrets: List,
) -> None:
    """
    Prints a report table summarizing information about secrets
    which failed certain conditions.

    If all lists are empty, nothing is printed and the
    function is exited.
    """
    secrets = live_secrets + unaudited_secrets + audited_real_secrets

    if len(secrets) == 0:
        return

    table = []

    for secret in secrets:
        table.append(
            [
                secret['failed_condition'],
                secret['type'],
                secret['filename'],
                secret['line'],
            ],
        )

    print(
        tabulate.tabulate(
            table,
            headers=['Failed Condition', 'Secret Type', 'Filename', 'Line'],
            tablefmt='simple',
        ),
    )


def print_stats(
    live_secrets: List,
    unaudited_secrets: List,
    audited_real_secrets: List,
    baseline_filename: str,
    fail_on_live: bool,
    fail_on_unaudited: bool,
    fail_on_audited_real: bool,
) -> None:
    """
    Given lists of secrets which failed certain conditions and a baseline file name,
    print a sentence summarizing aggregate stats.
    """
    secrets = audit.get_secrets_list_from_file(baseline_filename)

    secrets_failing_conditions = live_secrets + unaudited_secrets + audited_real_secrets

    if len(secrets_failing_conditions) == 0:
        print(
            '\n{} potential secrets in {} were reviewed.'
            ' All checks have passed.\n'.format(
                colorize(len(secrets), AnsiColor.BOLD),
                colorize(baseline_filename, AnsiColor.BOLD),
            ),
        )
        return

    stats = '\n{} potential secrets in {} were reviewed. Found'.format(
        colorize(len(secrets), AnsiColor.BOLD), colorize(baseline_filename, AnsiColor.BOLD),
    )

    if fail_on_live:
        stats += ' {} live secret{}'.format(
            colorize(len(live_secrets), AnsiColor.BOLD),
            's' if len(live_secrets) > 1 or len(live_secrets) == 0 else '',
        )

    if fail_on_unaudited:
        stats += '{} {} unaudited secret{},'.format(
            ',' if fail_on_live else '',
            colorize(len(unaudited_secrets), AnsiColor.BOLD),
            's' if len(unaudited_secrets) > 1 or len(unaudited_secrets) == 0 else '',
        )

    if fail_on_audited_real:
        stats += ' {} {} secret{} that {} audited as real.\n'.format(
            'and' if fail_on_live or fail_on_audited_real else '',
            colorize(len(audited_real_secrets), AnsiColor.BOLD),
            's' if len(audited_real_secrets) > 1 or len(audited_real_secrets) == 0 else '',
            'were' if len(audited_real_secrets) > 1 or len(audited_real_secrets) == 0 else 'was',
        )

    print(stats)


def print_summary(
    unaudited_return_code: int,
    live_return_code: int,
    audited_real_return_code: int,
    baseline_filename: str,
    fail_on_live: bool,
    fail_on_unaudited: bool,
    fail_on_audited_real: bool,
    omit_instructions=False,
) -> None:
    """
    Prints information about failed checks in a report,
    as well as how to remediate them.

    Instructions can optionally be omitted.
    """

    if unaudited_return_code == live_return_code == audited_real_return_code == 0:
        if fail_on_unaudited:
            print(
                '{}\n'.format(
                    colorize('\t- No unaudited secrets were found', AnsiColor.BOLD),
                ),
            )

        if fail_on_live:
            print(
                '{}\n'.format(
                    colorize('\t- No live secrets were found', AnsiColor.BOLD),
                ),
            )

        if fail_on_audited_real:
            print(
                '{}\n'.format(
                    colorize('\t- No secrets that were audited as real were found', AnsiColor.BOLD),
                ),
            )
        return

    print('\nFailed conditions:\n')

    if fail_on_unaudited and unaudited_return_code != 0:
        print(
            '{}\n'.format(
                colorize('\t- Unaudited secrets were found', AnsiColor.BOLD),
            ),
        )
        if omit_instructions is False:
            print(
                '\t\tRun detect-secrets audit {}, and audit all potential secrets.'.format(
                    baseline_filename,
                ),
            )
    if fail_on_live and live_return_code != 0:
        print(
            '{}\n'.format(
                colorize('\t- Live secrets were found', AnsiColor.BOLD),
            ),
        )
        if omit_instructions is False:
            print(
                '\t\tRevoke all live secrets and remove them from the codebase.'
                ' Afterwards, run detect-secrets scan --update {} to re-scan.'.format(
                    baseline_filename,
                ),
            )

    if fail_on_audited_real and audited_real_return_code != 0:
        print(
            '{}\n'.format(
                colorize('\t- Audited true secrets were found', AnsiColor.BOLD),
            ),
        )
        if omit_instructions is False:
            print(
                '\t\tRemove secrets meeting this condition from the codebase,'
                ' and run detect-secrets scan --update {} to re-scan.'.format(baseline_filename),
            )

    if omit_instructions is False:
        print('\nFor additional help, run detect-secrets audit --help.\n')
