import hashlib
import codecs
import json
from enum import Enum

from .common import get_baseline_from_file
from ..core.plugins.util import Plugin, get_mapping_from_secret_type_to_class
from ..core.scan import _get_lines_from_file, _scan_line
from ..core.potential_secret import PotentialSecret
from ..plugins.base import BasePlugin
from ..constants import VerifiedResult


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
    class_to_print: SecretClassToPrint = None
) -> None:
    plugins = get_mapping_from_secret_type_to_class()
    secrets = {}
    for filename, secret in get_baseline_from_file(baseline_file):
        verified_result = get_verified_result_from_boolean(secret.is_secret)
        if class_to_print != None and SecretClassToPrint.from_class(verified_result) != class_to_print:
            continue
        try:
            detections = get_potential_secrets(filename, plugins[secret.type](), secret.secret_hash)
        except:
            continue
        identifier = hashlib.sha512((secret.secret_hash + filename).encode('utf-8')).hexdigest()
        for detection in detections:
            if identifier in secrets:
                secrets[identifier]['lines'][detection.line_number] = get_line_content(filename, detection.line_number)
                if not secret.type in secrets[identifier]['types']:
                    secrets[identifier]['types'].append(secret.type)
                secrets[identifier]['category'] = get_prioritary_verified_result(verified_result, VerifiedResult[secrets[identifier]['category']]).name
            else:
                secrets[identifier] = {
                    'secrets': detection.secret_value,
                    'filename': filename,
                    'lines': {
                        detection.line_number: get_line_content(filename, detection.line_number)
                    },
                    'types': [
                        secret.type
                    ],
                    'category': verified_result.name
                }

    output = []
    for identifier in secrets:
        output.append(secrets[identifier])

    return output


def get_prioritary_verified_result(
    result1: VerifiedResult, 
    result2: VerifiedResult
) -> VerifiedResult:
    if result1.value > result2.value:
        return result1
    else: 
        return result2


def get_verified_result_from_boolean(
    is_secret: bool
) -> VerifiedResult:
    if is_secret == None:
        return VerifiedResult.UNVERIFIED
    elif is_secret:
        return VerifiedResult.VERIFIED_TRUE
    else:
        return VerifiedResult.VERIFIED_FALSE


def get_potential_secrets(
    filename: str,
    plugin: Plugin,
    secret_to_find: str
) -> [PotentialSecret]:
    """
    :returns: List of PotentialSecrets detected by a specific plugin in a file.
    """
    for lines in _get_lines_from_file(filename):
        for line_number, line in list(enumerate(lines, 1)):
            secrets = _scan_line(plugin, filename, line, line_number)
            for secret in secrets:
                if secret.secret_hash == secret_to_find:
                    yield secret


def get_line_content(
    filename: str,
    line_number: int
) -> str:
    """
    :returns: Line content from filename by line number.
    """
    content = codecs.open(filename, encoding='utf-8').read()
    if not content:
        return None
    return content.splitlines()[line_number - 1]