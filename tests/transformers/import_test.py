from detect_secrets.transformers import get_transformers


def test_success():
    transformers = get_transformers()
    assert {
        transformer.__class__.__name__
        for transformer in transformers
    } == {
        'ConfigFileTransformer',
        'EagerConfigFileTransformer',
        'YAMLTransformer',
    }
