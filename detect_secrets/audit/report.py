import codecs
import hashlib
from enum import Enum

from ..constants import VerifiedResult
from ..core.plugins.util import get_mapping_from_secret_type_to_class
from ..core.plugins.util import Plugin
from ..core.potential_secret import PotentialSecret
from ..core.scan import _get_lines_from_file
from ..core.scan import _scan_line
from .common import get_all_raw_secrets_from_file
from .common import get_baseline_from_file
from .common import get_raw_secret_line_from_file


class SecretClassToPrint(Enum):
    REAL_SECRET = 1
    FALSE_POSITIVE = 2

    def from_class(secret_class: VerifiedResult) -> Enum:
        if secret_class in [VerifiedResult.UNVERIFIED, VerifiedResult.VERIFIED_TRUE]:
            return SecretClassToPrint.REAL_SECRET
        else:
            return SecretClassToPrint.FALSE_POSITIVE


def generate_report(
    baseline_file: str,
    class_to_print: SecretClassToPrint = None,
) -> None:
    secrets = {}
    for filename, secret in get_baseline_from_file(baseline_file):
        verified_result = get_verified_result_from_boolean(secret.is_secret)
        if class_to_print is not None and SecretClassToPrint.from_class(verified_result) != class_to_print:  # noqa: E501
            continue
        detections = get_all_raw_secrets_from_file(secret)
        identifier = hashlib.sha512((secret.secret_hash + filename).encode('utf-8')).hexdigest()
        for detection in detections:
            if identifier in secrets:
                secrets[identifier]['lines'][detection.line_number] = get_raw_secret_line_from_file(detection)
                if secret.type not in secrets[identifier]['types']:
                    secrets[identifier]['types'].append(secret.type)
                secrets[identifier]['category'] = get_prioritary_verified_result(
                    verified_result,
                    VerifiedResult[secrets[identifier]['category']],
                ).name
            else:
                secrets[identifier] = {
                    'secrets': detection.secret_value,
                    'filename': filename,
                    'lines': {
                        detection.line_number: get_raw_secret_line_from_file(detection),
                    },
                    'types': [
                        secret.type,
                    ],
                    'category': verified_result.name,
                }

    output = []
    for identifier in secrets:
        output.append(secrets[identifier])

    return output


def get_prioritary_verified_result(
    result1: VerifiedResult,
    result2: VerifiedResult,
) -> VerifiedResult:
    if result1.value > result2.value:
        return result1
    else:
        return result2


def get_verified_result_from_boolean(
    is_secret: bool,
) -> VerifiedResult:
    if is_secret is None:
        return VerifiedResult.UNVERIFIED
    elif is_secret:
        return VerifiedResult.VERIFIED_TRUE
    else:
        return VerifiedResult.VERIFIED_FALSE
