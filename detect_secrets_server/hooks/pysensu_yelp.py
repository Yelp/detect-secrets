#!/usr/bin/python
from __future__ import absolute_import

import codecs

import pysensu_yelp
import yaml

from detect_secrets.core.log import CustomLog
from detect_secrets_server.hooks.base import BaseHook


CustomLogObj = CustomLog()


class PySensuYelpHook(BaseHook):  # pragma: no cover
    """This sends an alert to Sensu as specified in the pysensu configuration file."""

    def __init__(self, config_file):
        self.config_file = config_file

    def alert(self, secrets, repo_name):
        try:
            with codecs.open(self.config_file) as f:
                config_data = yaml.safe_load(f)

        except IOError:
            CustomLogObj.getLogger().error(
                'Unable to open pysensu config file: %s.', self.config_file
            )

            raise
        config_data['output'] = "In repo " + repo_name + "\n" + str(secrets)
        pysensu_yelp.send_event(**config_data)
