import os


def get_root_directory():       # pragma: no cover
    return os.path.realpath(
        os.path.join(
            os.path.dirname(__file__),
            '../',
        ),
    )


def get_relative_path(root, path):
    """Returns relative path, after following symlinks."""
    return os.path.realpath(
        os.path.join(root, path),
    )[len(os.getcwd() + '/'):]
