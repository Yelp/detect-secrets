from setuptools import find_packages
from setuptools import setup

setup(
    name='detect_secrets',
    description='Tool for detecting secrets in the codebase',
    author='Aaron Loo',
    packages=find_packages(exclude=(['test*', 'tmp*'])),
    install_requires=[
        'enum34',
        'future',
        'pyyaml',
        'unidiff',
    ],
    entry_points={
        'console_scripts': [
            'detect-secrets = detect_secrets.main:main',
            'detect-secrets-hook = detect_secrets.pre_commit_hook:main',
        ],
    },
    version='0.7.0',
)
