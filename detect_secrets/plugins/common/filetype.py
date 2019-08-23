import os
from enum import Enum


class FileType(Enum):
    CLS = 0
    GO = 1
    JAVA = 2
    JAVASCRIPT = 3
    PHP = 4
    OBJECTIVE_C = 5
    PYTHON = 6
    SWIFT = 7
    YAML = 8
    OTHER = 9


EXTENSION_TO_FILETYPE = {
    '.cls': FileType.CLS,
    '.eyaml': FileType.YAML,
    '.go': FileType.GO,
    '.java': FileType.JAVA,
    '.js': FileType.JAVASCRIPT,
    '.m': FileType.OBJECTIVE_C,
    '.php': FileType.PHP,
    '.py': FileType.PYTHON,
    '.pyi': FileType.PYTHON,
    '.swift': FileType.SWIFT,
    '.yaml': FileType.YAML,
    '.yml': FileType.YAML,
}


def determine_file_type(filename):
    """
    :param filename: str

    :rtype: FileType
    """
    _, file_extension = os.path.splitext(filename)
    return EXTENSION_TO_FILETYPE.get(
        file_extension,
        FileType.OTHER,
    )
