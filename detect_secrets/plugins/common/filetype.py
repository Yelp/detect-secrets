from enum import Enum


class FileType(Enum):
    JAVASCRIPT = 0
    PHP = 1
    PYTHON = 2
    OTHER = 3


def determine_file_type(filename):
    """
    :param filename: str

    :rtype: FileType
    """
    if filename.endswith('.js'):
        return FileType.JAVASCRIPT
    elif filename.endswith('.py'):
        return FileType.PYTHON
    elif filename.endswith('.php'):
        return FileType.PHP
    return FileType.OTHER
