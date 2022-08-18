"""
This plugin searches for Grafana tokens
"""
import re

from .base import RegexBasedDetector

class GrafanaDetector(RegexBasedDetector):
    """Scans for BGrafana tokens"""
    secret_type = 'Grafana Token'

    denylist = [
        # Grafana Cloud API Token & Grafana API Key
        # Merging the two as there is an issue in the engine which will false-positive any 
        # Grafana Cloud API Token as the actual data resembles the Grafana API Key
        # e.g. contains eyJrIjoi, but does not match the rest of the pattern
        re.compile(r'glc_[A-Za-z0-9+/]{32,}={0,2}|eyJrIjoi[A-Za-z0-9]{70,}={0,2}'),
        # Grafana Service Account Token
        re.compile(r'glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}'),
        # Grafana API Key
    ]
