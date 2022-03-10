from detect_secrets.core.audit import get_secrets_list_from_file
from detect_secrets.core.report.constants import ReportCheckResult
from detect_secrets.core.report.constants import ReportExitCode
from detect_secrets.core.report.constants import ReportSecretType


def fail_on_unaudited(baseline_filename: str) -> ReportCheckResult:
    """
    Given a baseline filename, checks if that baseline contains
    any secret results which have not been audited yet.

    If so, the list of unaudited secrets is included in the return
    value.
    """
    secrets = get_secrets_list_from_file(baseline_filename)
    non_audited_secrets = []

    for filename, secret in secrets:
        if 'is_secret' not in secret or secret['is_secret'] is None:
            unaudited_secret = {
                'failed_condition': ReportSecretType.UNAUDITED.value,
                'filename': filename,
                'line': secret['line_number'],
                'type': secret['type'],
            }

            non_audited_secrets.append(unaudited_secret)

    if len(non_audited_secrets) > 0:
        return ReportCheckResult(ReportExitCode.FAIL.value, non_audited_secrets)

    return ReportCheckResult(ReportExitCode.PASS.value, [])


def fail_on_live(baseline_filename: str) -> ReportCheckResult:
    """
    Given a baseline filename, checks if that baseline contains
    any active verified secrets.

    If so, the list of verified secrets is included in the return
    value.
    """
    secrets = get_secrets_list_from_file(baseline_filename)
    live_secrets = []

    for filename, secret in secrets:
        if 'is_verified' in secret and secret['is_verified'] is True:
            live_secret = {
                'failed_condition': ReportSecretType.LIVE.value,
                'filename': filename,
                'line': secret['line_number'],
                'type': secret['type'],
            }
            live_secrets.append(live_secret)

    if len(live_secrets) > 0:
        return ReportCheckResult(ReportExitCode.FAIL.value, live_secrets)

    return ReportCheckResult(ReportExitCode.PASS.value, [])


def fail_on_audited_real(baseline_filename: str) -> ReportCheckResult:
    """
    Given a baseline filename, checks if that baseline contains
    any secrets which have been marked as real during the auditing process.

    If so, the list of audited real secrets is included in the return
    value.
    """
    secrets = get_secrets_list_from_file(baseline_filename)
    audited_true_secrets = []

    for filename, secret in secrets:
        if 'is_secret' in secret and secret['is_secret'] is True:
            audited_true_secret = {
                'failed_condition': ReportSecretType.AUDITED_REAL.value,
                'filename': filename,
                'line': secret['line_number'],
                'type': secret['type'],
            }
            audited_true_secrets.append(audited_true_secret)

    if len(audited_true_secrets) > 0:
        return ReportCheckResult(ReportExitCode.FAIL.value, audited_true_secrets)

    return ReportCheckResult(ReportExitCode.PASS.value, [])
