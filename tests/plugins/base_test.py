from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class


def test_ensure_all_plugins_have_unique_secret_types():
    secret_types = set()
    for plugin_type in get_mapping_from_secret_type_to_class().values():
        secret_types.add(plugin_type.secret_type)

    assert len(secret_types) == len(get_mapping_from_secret_type_to_class())
