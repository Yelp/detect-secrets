from enum import Enum


class FileType(Enum):
    CLS = 0
    GO = 1
    JAVA = 2
    JAVASCRIPT = 3
    PHP = 4
    PYTHON = 5
    SWIFT = 6
    YAML = 7
    OTHER = 8


def determine_file_type(filename):
    """
    :param filename: str

    :rtype: FileType
    """
    if filename.endswith('.cls'):
        return FileType.CLS
    elif filename.endswith('.go'):
        return FileType.GO
    elif filename.endswith('.java'):
        return FileType.JAVA
    elif filename.endswith('.js'):
        return FileType.JAVASCRIPT
    elif filename.endswith('.php'):
        return FileType.PHP
    elif filename.endswith('.py'):
        return FileType.PYTHON
    elif filename.endswith('.swift'):
        return FileType.SWIFT
    elif (
        filename.endswith(
            ('.eyaml', '.yaml', '.yml'),
        )
    ):
        return FileType.YAML
    return FileType.OTHER
