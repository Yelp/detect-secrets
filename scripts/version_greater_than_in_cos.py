import sys

import requests
from packaging.version import parse


def version_greater_than_in_cos(new_version):
    # check if 'new' version greater than the one currently stored in cos
    resp = requests.get('https://ibm.biz/detect-secrets-version')
    latest_version = parse(resp.text)
    new_version = parse(new_version)
    if new_version > latest_version:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == '__main__':
    version_greater_than_in_cos(sys.argv[1])
