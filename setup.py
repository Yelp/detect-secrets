from setuptools import find_packages
from setuptools import setup

setup(
    name='detect_secrets',
    description='Tool for detecting secrets in the codebase',
    author='Aaron Loo',
    packages=find_packages(exclude=(['test*', 'tmp*'])),
    install_requires=[
        'chainmap',
        'boto3',
        'enum34',
        'future',
        'pysensu_yelp',
        'pyyaml',
        'unidiff',
    ],
    entry_points={
        'console_scripts': [
            'detect-secrets = detect_secrets.main:main',
            'detect-secrets-hook = detect_secrets.pre_commit_hook:main',
            'detect-secrets-server = detect_secrets.server:main',
        ],
    },
    version='0.6.3',
)
