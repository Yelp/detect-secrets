import os
from enum import Enum


class FileType(Enum):
    CLS = 0
    EXAMPLE = 1
    GO = 2
    JAVA = 3
    JAVASCRIPT = 4
    PHP = 5
    OBJECTIVE_C = 6
    PYTHON = 7
    SWIFT = 8
    TERRAFORM = 9
    YAML = 10
    INI = 11
    PROPERTIES = 12
    XML = 13
    C = 14
    CPP = 15
    CSHARP = 16
    BASH = 17
    POWERSHELL = 18
    OTHER = 19


EXTENSION_TO_FILETYPE = {
    '.cls': FileType.CLS,
    '.example': FileType.EXAMPLE,
    '.eyaml': FileType.YAML,
    '.go': FileType.GO,
    '.java': FileType.JAVA,
    '.js': FileType.JAVASCRIPT,
    '.jsx': FileType.JAVASCRIPT,
    '.m': FileType.OBJECTIVE_C,
    '.php': FileType.PHP,
    '.py': FileType.PYTHON,
    '.pyi': FileType.PYTHON,
    '.swift': FileType.SWIFT,
    '.tf': FileType.TERRAFORM,
    '.yaml': FileType.YAML,
    '.yml': FileType.YAML,
    '.ini': FileType.INI,
    '.properties': FileType.PROPERTIES,
    '.xml': FileType.XML,
    '.c': FileType.C,
    '.cpp': FileType.CPP,
    '.cs': FileType.CSHARP,
    '.sh': FileType.BASH,
    '.ps1': FileType.POWERSHELL,
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
