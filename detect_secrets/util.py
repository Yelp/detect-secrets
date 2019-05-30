import os


def get_root_directory():
    return os.path.realpath(
        os.path.join(
            os.path.dirname(__file__),
            '../',
        ),
    )
