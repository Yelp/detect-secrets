#!/usr/bin/python


class BaseHook(object):  # pragma: no cover
    """This is an abstract class to define Hooks API. A hook is an alerting system
    that allows you connect your server scanning results to your larger ecosystem
    (eg. email alerts, IRC pings...)"""

    def alert(self, data):
        """
        :param data: dictionary; where keys are filenames
        """
        raise NotImplementedError
