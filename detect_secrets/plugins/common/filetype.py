from enum import Enum


class FileType(Enum):
    CLS = 0
    JAVA = 1
    JAVASCRIPT = 2
    PHP = 3
    PYTHON = 4
    YAML = 5
    OTHER = 6


def determine_file_type(filename):
    """
    :param filename: str

    :rtype: FileType
    """
    if filename.endswith('.cls'):
        return FileType.CLS
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
