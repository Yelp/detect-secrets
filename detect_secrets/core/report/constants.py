from enum import Enum
from typing import List
from typing import NamedTuple


class ReportSecretType(Enum):
    AUDITED_REAL = 'Audited as real'
    UNAUDITED = 'Unaudited'
    LIVE = 'Live'


class ReportExitCode(Enum):
    PASS = 0
    FAIL = 1


ReportCheckResult = NamedTuple(
    'ReportCheckResult',
    [('report_exit_code', ReportExitCode), ('secrets_failing_condition', List)],
)
