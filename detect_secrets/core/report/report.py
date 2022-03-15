import sys
from argparse import ArgumentParser

from detect_secrets.core.report.conditions import fail_on_audited_real
from detect_secrets.core.report.conditions import fail_on_live
from detect_secrets.core.report.conditions import fail_on_unaudited
from detect_secrets.core.report.constants import ReportExitCode
from detect_secrets.core.report.output import print_json_report
from detect_secrets.core.report.output import print_stats
from detect_secrets.core.report.output import print_summary
from detect_secrets.core.report.output import print_table_report


def execute(args) -> None:
    """
    Executes a report based off the given arguments.

    This feature extends the audit subcommand; it is recommended to be run as a
    CI / CD build stage for users who would like to have a Detect Secrets report
    in their pipeline.

    It will cause Detect Secrets to exit with an error code if secrets
    within a baseline fail a user-provided set of conditions:

    1. if they are active (--fail-on-live)
    2. if have not been audited  (--fail-on-unaudited)
    3. if they have been marked as real secrets when audited (--fail-on-audited-real)

    A detailed report will be output that lists information about the secrets which failed
    said conditions, including line number, filename, condition failed.There will be no
    raw secret values in this output

    Alternatively, assuming all conditions pass, Detect secrets will complete with zero exit status,
    outputting a short summary stating that the checks passed, allowing the CI / CD build to
    continue onto the next stage.

    If no fail-on options are provided, all of the conditions will be
    checked by default, but the report will always exit with zero.
    """
    unaudited_secrets = live_secrets = audited_real_secrets = []
    unaudited_return_code = live_return_code = audited_real_return_code = ReportExitCode.PASS.value
    default_conditions = False

    # If no fail conditions provided, run report using all fail conditions, but exit with 0
    if (
        args.report
        and not args.fail_on_unaudited
        and not args.fail_on_audited_real
        and not args.fail_on_live
    ):
        default_conditions = True

    if args.fail_on_unaudited or default_conditions:
        (unaudited_return_code, unaudited_secrets) = fail_on_unaudited(
            args.filename[0],
        )

    if args.fail_on_live or default_conditions:
        (live_return_code, live_secrets) = fail_on_live(args.filename[0])

    if args.fail_on_audited_real or default_conditions:
        (audited_real_return_code, audited_real_secrets) = fail_on_audited_real(
            args.filename[0],
        )

    if args.json:
        print_json_report(
            live_secrets,
            unaudited_secrets,
            audited_real_secrets,
            args.filename[0],
            True if default_conditions else args.fail_on_live,
            True if default_conditions else args.fail_on_unaudited,
            True if default_conditions else args.fail_on_audited_real,
        ),
    else:
        print_stats(
            live_secrets,
            unaudited_secrets,
            audited_real_secrets,
            args.filename[0],
            True if default_conditions else args.fail_on_live,
            True if default_conditions else args.fail_on_unaudited,
            True if default_conditions else args.fail_on_audited_real,
        )
        print_table_report(
            live_secrets,
            unaudited_secrets,
            audited_real_secrets,
        )
        print_summary(
            unaudited_return_code,
            live_return_code,
            audited_real_return_code,
            args.filename[0],
            True if default_conditions else args.fail_on_live,
            True if default_conditions else args.fail_on_unaudited,
            True if default_conditions else args.fail_on_audited_real,
            True if args.omit_instructions else False,
        )

    if (
        unaudited_return_code
        == live_return_code
        == audited_real_return_code
        == ReportExitCode.PASS.value
    ):
        sys.exit(ReportExitCode.PASS.value)
    elif default_conditions:
        sys.exit(ReportExitCode.PASS.value)
    else:
        sys.exit(ReportExitCode.FAIL.value)


def validate_args(args, auditParser: ArgumentParser) -> None:
    """
    argsparse does not have a built-in option for mutually inclusive arguments,
    so we have to do the additional report argument validation ourselves.
    Specifically, there is no way to use argsparse to allow the report-specific.
    arguments to only be used when --report is included.
    """
    if args.report:
        return

    if args.fail_on_unaudited:
        auditParser.error(
            'argument --fail-on-unaudited: not allowed without argument --report',
        )

    if args.fail_on_live:
        auditParser.error(
            'argument --fail-on-live: not allowed without argument --report',
        )

    if args.fail_on_audited_real:
        auditParser.error(
            'argument --fail-on-audited-real: not allowed without argument --report',
        )

    if args.omit_instructions:
        auditParser.error(
            'argument --omit-instructions: not allowed without argument --report',
        )

    if args.json:
        auditParser.error(
            'argument --json: not allowed without argument --report',
        )
