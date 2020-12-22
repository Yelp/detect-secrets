import hashlib
import codecs
import json
from enum import Enum

from .io import print_message
from ..core.plugins.util import Plugin, get_mapping_from_secret_type_to_class
from ..core.scan import _get_lines_from_file, _scan_line
from ..core.potential_secret import PotentialSecret
from ..plugins.base import BasePlugin


class SecretClass(Enum):
    TRUE_POSITIVE = 1
    FALSE_POSITIVE = 2
    UNKNOWN = 3

    def from_boolean(is_secret: bool) -> Enum:
        if is_secret == None:
            return SecretClass.UNKNOWN
        elif is_secret:
            return SecretClass.TRUE_POSITIVE
        else:
            return SecretClass.FALSE_POSITIVE

    def to_string(self) -> str:
        return self.name

    def get_prioritary(self, secret_class: str) -> Enum:
        try:
            to_compare = SecretClass[secret_class]
        except:
            return self
        if to_compare.value < self.value:
            return secret_class
        else:
            return self


class SecretClassToPrint(Enum):
    REAL_SECRET = 1
    FALSE_POSITIVE = 2

    def from_class(secret_class: SecretClass) -> Enum:
        if secret_class in [SecretClass.UNKNOWN, SecretClass.TRUE_POSITIVE]:
            return SecretClassToPrint.REAL_SECRET
        else:
            return SecretClassToPrint.FALSE_POSITIVE        


def print_report(
    baseline_file: str,
    class_to_print: SecretClassToPrint = None
) -> None:
    baseline = json.load(codecs.open(baseline_file, encoding='utf-8'))
    details = get_secrets_details_from_baseline(baseline)
    plugins = get_mapping_from_secret_type_to_class()
    secrets = {}
    for filename, secret_type, secret_hash, is_secret in details:
        secret_class = SecretClass.from_boolean(is_secret)
        if class_to_print != None and SecretClassToPrint.from_class(secret_class) != class_to_print:
            continue
        try:
            detections = get_potential_secrets(filename, plugins[secret_type](), secret_hash)
        except:
            continue
        identifier = hashlib.sha512((secret_hash + filename).encode('utf-8')).hexdigest()
        for detection in detections:
            if identifier in secrets:
                secrets[identifier]['lines'][detection.line_number] = get_line_content(filename, detection.line_number)
                if not secret_type in secrets[identifier]['types']:
                    secrets[identifier]['types'].append(secret_type)
                secrets[identifier]['class'] = secret_class.get_prioritary(secrets[identifier]['class']).to_string()
            else:
                finding = {}
                finding['secret'] = detection.secret_value
                finding['filename'] = filename
                finding['lines'] = {}
                finding['lines'][detection.line_number] = get_line_content(filename, detection.line_number)
                finding['types'] = [secret_type]
                finding['class'] = secret_class.to_string()
                secrets[identifier] = finding

    output = []
    for identifier in secrets:
        output.append(secrets[identifier])

    print_message(json.dumps(output, indent=4, sort_keys=True))

    
def get_secrets_details_from_baseline(
    baseline: str
) -> [(str, str, str, bool)]:
    """
    :returns: Details of each secret present in the baseline file.
    """
    for filename, secrets in baseline['results'].items():
        for secret in secrets:
            yield filename, secret['type'], secret['hashed_secret'], secret['is_secret']


def get_secret_class(
    is_secret: bool
) -> str:
    """
    :returns: Secret class as string.
    """
    return 'Unknown' if is_secret == None else 'True positive' if is_secret else 'False positive'


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