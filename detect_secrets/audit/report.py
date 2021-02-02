import hashlib
from enum import Enum
from typing import Callable

from ..constants import VerifiedResult
from .common import get_all_secrets_from_file
from .common import get_baseline_from_file
from .common import LineGetter
from .common import open_file


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
    line_getter_factory: Callable[[str], 'LineGetter'] = open_file,
) -> None:
    secrets = {}
    for filename, secret in get_baseline_from_file(baseline_file):
        verified_result = get_verified_result_from_boolean(secret.is_secret)
        if class_to_print is not None and SecretClassToPrint.from_class(verified_result) != class_to_print:  # noqa: E501
            continue
        detections = get_all_secrets_from_file(secret)
        identifier = hashlib.sha512((secret.secret_hash + filename).encode('utf-8')).hexdigest()
        line_getter = line_getter_factory(filename)
        for detection in detections:
            if identifier in secrets:
                secrets[identifier]['lines'][detection.line_number] = line_getter.lines[detection.line_number - 1]  # noqa: E501
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
                        detection.line_number: line_getter.lines[detection.line_number - 1],
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
