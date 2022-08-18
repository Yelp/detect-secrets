"""
This plugin searches for Grafana tokens
"""
import re

from .base import RegexBasedDetector

class GrafanaDetector(RegexBasedDetector):
    """Scans for BGrafana tokens"""
    secret_type = 'Grafana Token'

    denylist = [
        # Grafana Cloud API Token
        #re.compile(r'glc_[A-Za-z0-9+/]{32,}={0,2}'),
        re.compile(r'glc_[A-Za-z0-9+/]{32,}={0,2}|eyJrIjoi[A-Za-z0-9]{70,}={0,2}'),
        # Grafana Service Account Token
        re.compile(r'glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}'),
        # Grafana API Key
        #re.compile(r'eyJrIjoi[A-Za-z0-9]{70,}={0,2}'),
    ]
