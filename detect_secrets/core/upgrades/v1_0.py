from typing import Any
from typing import Dict


def upgrade(baseline: Dict[str, Any]) -> None:
    for function in [
        _migrate_filters,
        _rename_high_entropy_string_arguments,
        _migrate_custom_plugins,
    ]:
        function(baseline)


def _migrate_filters(baseline: Dict[str, Any]) -> None:
    """
    In v1.0.0, we introduced the idea of `filters`. This consolidated a variety of different
    false positive filters into a configurable layout. To reduce upgrade friction, this will
    contain the default filters used before this version upgrade.
    """
    baseline['filters_used'] = [
        {
            'path': 'detect_secrets.filters.heuristic.is_sequential_string',
        },
        {
            'path': 'detect_secrets.filters.heuristic.is_potential_uuid',
        },
        {
            'path': 'detect_secrets.filters.heuristic.is_likely_id_string',
        },
    ]

    if baseline.get('exclude'):
        if baseline['exclude'].get('files'):
            baseline['filters_used'].append({
                'path': 'detect_secrets.filters.regex.should_exclude_file',
                'pattern': baseline['exclude']['files'],
            })

        if baseline['exclude'].get('lines'):
            baseline['filters_used'].append({
                'path': 'detect_secrets.filters.regex.should_exclude_line',
                'pattern': baseline['exclude']['lines'],
            })

        baseline.pop('exclude')

    if baseline.get('word_list'):
        if baseline['word_list']['file']:
            baseline['filters_used'].append({
                'path': 'detect_secrets.filters.wordlist.should_exclude_secret',
                'min_length': 3,
                'file_name': baseline['word_list']['file'],
                'file_hash': baseline['word_list']['hash'],
            })

        baseline.pop('word_list')


def _rename_high_entropy_string_arguments(baseline: Dict[str, Any]) -> None:
    """
    During the great refactor for v1.0.0, we also decided to rename these arguments for
    consistency and simplicity.
    """
    for plugin in baseline['plugins_used']:
        if plugin['name'] == 'Base64HighEntropyString':
            plugin['limit'] = plugin.pop('base64_limit')

        elif plugin['name'] == 'HexHighEntropyString':
            plugin['limit'] = plugin.pop('hex_limit')

    # TODO: KeywordDetector?


def _migrate_custom_plugins(baseline: Dict[str, Any]) -> None:
    # TODO
    pass
