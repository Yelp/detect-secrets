import sys
if sys.version_info.major == 2:
    sys.exit(
        'Sorry, Python 2 is no longer supported by detect-secrets. Refer to' +
        ' http://ibm.biz/upgrade-to-py3 for instructions on upgraing to Python 3.',
    )

from setuptools import find_packages
from setuptools import setup

from detect_secrets import VERSION


setup(
    name='detect_secrets',
    packages=find_packages(exclude=(['test*', 'tmp*'])),
    version=VERSION,
    description='Tool for detecting secrets in the codebase',
    long_description=(
        'Check out detect-secrets on `GitHub ' +
        '<https://github.com/IBM/detect-secrets>`_!'
    ),
    url='hhttps://github.com/IBM/detect-secrets',
    keywords=['secret-management', 'pre-commit', 'security', 'entropy-checks'],
    install_requires=[
        'pyyaml',
        'requests',
        'boxsdk[jwt]',
        'packaging',
        'tabulate',
    ],
    extras_require={
        'word_list': [
            'pyahocorasick',
        ],
        'db2': [
            'ibm_db',
        ],
    },
    entry_points={
        'console_scripts': [
            'detect-secrets = detect_secrets.main:main',
            'detect-secrets-hook = detect_secrets.pre_commit_hook:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: Apache Software License',
        'Intended Audience :: Developers',
        'Topic :: Software Development',
        'Topic :: Utilities',
        'Environment :: Console',
        'Operating System :: OS Independent',
        'Development Status :: 5 - Production/Stable',
    ],
)
