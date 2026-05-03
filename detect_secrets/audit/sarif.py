"""
Convert a detect-secrets baseline into a SARIF 2.1.0 document.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
SARIF is consumed by GitHub code scanning, GitLab, Azure DevOps, Sonar, etc.,
which all expose findings in their UI when ingesting the format below.

The conversion is deliberately a thin layer over ``audit.report.generate_report``
so the SARIF view is always consistent with what users already see via
``detect-secrets audit --report``.
"""
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Tuple

from ..__version__ import VERSION
from ..constants import VerifiedResult
from .common import LineGetter
from .common import open_file
from .report import generate_report
from .report import SecretClassToPrint


SARIF_VERSION = '2.1.0'
SARIF_SCHEMA = (
    'https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json'
)
TOOL_NAME = 'detect-secrets'
TOOL_URI = 'https://github.com/Yelp/detect-secrets'

# SARIF "kind" values per spec section 3.27.9.
_KIND_TRUE_POSITIVE = 'open'  # i.e. an open finding requiring action
_KIND_FALSE_POSITIVE = 'review'  # under triage / not deemed a true positive


def generate_sarif_report(
    baseline_file: str,
    class_to_print: SecretClassToPrint = None,
    line_getter_factory: Callable[[str], 'LineGetter'] = open_file,
) -> Dict[str, Any]:
    """
    Build a SARIF 2.1.0 dict from a detect-secrets baseline file.

    Args:
        baseline_file: Path to the baseline JSON.
        class_to_print: Optional filter; mirrors ``audit.report.generate_report``.
        line_getter_factory: Factory for opening source files (overridable for
            tests).
    """
    report = generate_report(
        baseline_file=baseline_file,
        class_to_print=class_to_print,
        line_getter_factory=line_getter_factory,
    )

    rules: Dict[str, Dict[str, Any]] = {}
    rule_index: Dict[str, int] = {}
    results: List[Dict[str, Any]] = []

    for entry in report['results']:
        filename = entry['filename']
        verified_result = VerifiedResult[entry['category']]
        kind = (
            _KIND_FALSE_POSITIVE
            if SecretClassToPrint.from_class(verified_result)
            == SecretClassToPrint.FALSE_POSITIVE
            else _KIND_TRUE_POSITIVE
        )

        for secret_type in entry['types']:
            rule_id = secret_type
            if rule_id not in rules:
                rules[rule_id] = {
                    'id': rule_id,
                    'name': rule_id,
                    'shortDescription': {
                        'text': f'detect-secrets plugin: {rule_id}',
                    },
                    'helpUri': TOOL_URI,
                }
                rule_index[rule_id] = len(rules) - 1

            for line_number, line_text in entry['lines'].items():
                results.append({
                    'ruleId': rule_id,
                    'ruleIndex': rule_index[rule_id],
                    'level': 'error',
                    'kind': kind,
                    'message': {
                        'text': (
                            f'Potential secret detected by {rule_id}: '
                            f'{verified_result.name.lower().replace("_", " ")}.'
                        ),
                    },
                    'locations': [
                        {
                            'physicalLocation': {
                                'artifactLocation': {
                                    'uri': filename,
                                },
                                'region': {
                                    'startLine': int(line_number),
                                    'snippet': {
                                        'text': line_text.rstrip('\n'),
                                    },
                                },
                            },
                        },
                    ],
                    'partialFingerprints': {
                        # Stable across runs, doesn't expose the secret.
                        'detectSecretsHash/v1': (
                            f'{filename}:{rule_id}:{line_number}'
                        ),
                    },
                    'properties': {
                        'category': entry['category'],
                    },
                })

    return {
        '$schema': SARIF_SCHEMA,
        'version': SARIF_VERSION,
        'runs': [
            {
                'tool': {
                    'driver': {
                        'name': TOOL_NAME,
                        'version': VERSION,
                        'semanticVersion': VERSION,
                        'informationUri': TOOL_URI,
                        'rules': list(rules.values()),
                    },
                },
                'results': results,
            },
        ],
    }


__all__ = ('generate_sarif_report',)


# Re-export Tuple to keep mypy happy for callers that import from this module.
_ = Tuple  # type: ignore[misc]
