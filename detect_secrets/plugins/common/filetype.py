from enum import Enum


class FileType(Enum):
    CLS = 0
    JAVASCRIPT = 1
    PHP = 2
    PYTHON = 3
    YAML = 4
    OTHER = 5


def determine_file_type(filename):
    """
    :param filename: str

    :rtype: FileType
    """
    if filename.endswith('.cls'):
        return FileType.CLS
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
