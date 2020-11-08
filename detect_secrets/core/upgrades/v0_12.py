from typing import Any
from typing import Dict


def upgrade(baseline: Dict[str, Any]) -> None:
    if 'exclude_regex' in baseline:
        baseline['exclude'] = {
            'files': None,
            'lines': baseline.pop('exclude_regex'),
        }

    baseline['word_list'] = {
        'file': None,
        'hash': None,
    }
