import os

import pytest

from detect_secrets import filters
from detect_secrets.plugins.private_key import PrivateKeyDetector
from detect_secrets.settings import transient_settings


class TestShouldExcludeSecret:
    @staticmethod
    @pytest.fixture(autouse=True)
    def initialize():
        filters.gibberish.initialize(
            model_path=os.path.join(filters.gibberish.__path__[0], 'rfc.model'),
        )

        try:
            yield
        finally:
            filters.gibberish.get_model.cache_clear()

    @staticmethod
    @pytest.mark.parametrize(
        'secret',
        (
            'this-is-a-bad-password',

            # URLs (which have been traditionally picked up by Base64HighEntropyString)
            # are now excluded!
            '/biz_user/NCIygBmcWTENrE1n06oprA/business_ids/v1',

            # same thing with long strings
            'k8s-KUBE_CLUSTER-ca/issue/k8s-prometheus-adapter',
        ),
    )
    def test_success(secret):
        assert filters.gibberish.should_exclude_secret(secret)

    @staticmethod
    def test_ignores_hex_strings():
        assert not filters.gibberish.should_exclude_secret('2b00042f7481c7b056c4b410d28f33cf')

    @staticmethod
    def test_does_not_affect_private_keys():
        assert not filters.gibberish.should_exclude_secret(
            'BEGIN PRIVATE KEY',
            plugin=PrivateKeyDetector(),
        )


def test_load_from_baseline():
    with transient_settings({
        'filters_used': [{
            'path': 'detect_secrets.filters.gibberish.should_exclude_secret',
            'model': os.path.join(filters.gibberish.__path__[0], 'rfc.model'),
            'file_hash': '00b672f709e9bf51fe2e09abe247ac3b6415d645',
            'limit': 3.7,
        }],
    }):
        assert filters.gibberish.should_exclude_secret('clearly-not-a-secret')
