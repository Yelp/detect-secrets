#!/usr/bin/python
import logging
import sys


class CustomLog(logging.getLoggerClass()):  # pragma: no cover

    log_format_string = '[%(module)s]\t%(levelname)s\t%(message)s'

    # See CustomLog.enableDebug
    debug_mode = 0

    def __init__(self, debug_mode=None, formatter=None, *args, **kwargs):
        """
        :param name:       string; used for declaring log channels.
        :param debug_mode: debug level for this specific logger instance.
        :param formatter:  string; for custom formatting
        """
        super(CustomLog, self).__init__('', *args, **kwargs)

        if debug_mode is not None:
            self.debug_mode = debug_mode

        if formatter is None:
            self.formatter = logging.Formatter(CustomLog.log_format_string)
        elif isinstance(formatter, str):
            self.formatter = logging.Formatter(formatter)

    @classmethod
    def enableDebug(cls, verbose_level):
        """Configure the global verbosity of logs

        :param verbose_level: integer; between 0-2
        """
        cls.debug_mode = verbose_level

    def getLogger(self, name=None):
        log = logging.getLogger(name)

        debug_mode = self.debug_mode if self.debug_mode is not None else CustomLog.debug_mode

        # Apply custom default options
        log_level = logging.ERROR
        if debug_mode == 1:
            log_level = logging.INFO
        elif debug_mode == 2:
            log_level = logging.DEBUG

        log.setLevel(log_level)

        if self.formatter:
            log.handlers = []
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(self.formatter)
            log.addHandler(handler)

        logging.captureWarnings(True)

        return log
