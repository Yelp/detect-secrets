from enum import Enum


class FileType(Enum):
    CLS = 0
    GO = 1
    JAVA = 2
    JAVASCRIPT = 3
    PHP = 4
    PYTHON = 5
    YAML = 6
    OTHER = 7


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
    elif (
        filename.endswith(
            ('.yaml', '.yml'),
        )
    ):
        return FileType.YAML
    return FileType.OTHER
