import logging
import sys


def get_logger(name=None, format_string=None):
    """
    :type name: str
    :param name: used for declaring log channels.

    :type format_string: str
    :param format_string: for custom formatting
    """
    logging.captureWarnings(True)
    log = logging.getLogger(name)

    # Bind custom method to instance.
    # Source: https://stackoverflow.com/a/2982
    log.set_debug_level = _set_debug_level.__get__(log)
    log.set_debug_level(0)

    if not format_string:
        format_string = '[%(module)s]\t%(levelname)s\t%(message)s'

    # Setting up log formats
    log.handlers = []
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter(format_string),
    )
    log.addHandler(handler)

    return log


def _set_debug_level(self, debug_level):
    """
    :type debug_level: int, between 0-2
    :param debug_level: configure verbosity of log
    """
    mapping = {
        0: logging.ERROR,
        1: logging.INFO,
        2: logging.DEBUG,
    }

    self.setLevel(
        mapping[min(debug_level, 2)],
    )


log = get_logger()
