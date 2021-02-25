from pathlib import Path

from setuptools import find_packages
from setuptools import setup


def get_version():
    """Parse package __version__.py to get version."""
    versionpy = (Path('detect_secrets') / '__version__.py').read_text()
    return versionpy.split("'")[1]


VERSION = get_version()


with open('README.md') as f:
    long_description = f.read()


setup(
    name='detect_secrets',
    packages=find_packages(exclude=(['test*', 'tmp*'])),
    version=VERSION,
    description='Tool for detecting secrets in the codebase',
    long_description=long_description,
    long_description_content_type='text/markdown',
    license='Copyright Yelp, Inc. 2020',
    author='Aaron Loo',
    author_email='aaronloo@yelp.com',
    url='https://github.com/Yelp/detect-secrets',
    download_url='https://github.com/Yelp/detect-secrets/archive/{}.tar.gz'.format(VERSION),
    keywords=['secret-management', 'pre-commit', 'security', 'entropy-checks'],
    install_requires=[
        'pyyaml',
        'requests',
    ],
    extras_require={
        'word_list': [
            'pyahocorasick',
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
