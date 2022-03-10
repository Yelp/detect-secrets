from enum import Enum
from typing import List
from typing import NamedTuple
from typing import TypedDict


class ReportSecretType(Enum):
    AUDITED_REAL = 'Audited as real'
    UNAUDITED = 'Unaudited'
    LIVE = 'Live'


class ReportExitCode(Enum):
    PASS = 0
    FAIL = 1


ReportStats = TypedDict(
    'ReportStats',
    {'reviewed': int, 'live': int, 'unaudited': int, 'audited_real': int},
)

ReportedSecret = TypedDict(
    'ReportedSecret',
    {'failed_condition': ReportSecretType, 'filename': str, 'line': int, 'type': str},
)

ReportJson = TypedDict('ReportJson', {'stats': ReportStats, 'secrets': List[ReportedSecret]})

ReportCheckResult = NamedTuple(
    'ReportCheckResult',
    [('report_exit_code', ReportExitCode), ('secrets_failing_condition', List[ReportedSecret])],
)
