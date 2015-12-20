#!/usr/bin/env python3
from setuptools import setup, find_packages

with open('README.md') as file:
    long_description = file.read()

setup(
    name='mammon',
    version='0.0.0',
    description='Legacy-free IRCv3.2 server built ontop of ircreactor.',
    long_description=long_description,
    author='William Pitcock',
    author_email='nenolod@dereferenced.org',
    url='https://github.com/mammon-ircd/mammon',
    packages=find_packages(),
    scripts=['mammond'],
    data_files=[('mammon', ['mammond.yml'])],
    install_requires=['docopt', 'PyYAML', 'passlib', 'ircreactor', 'ircmatch'],
    dependency_links=[
        'git+https://github.com/mammon-ircd/ircreactor.git#egg=ircreactor',
    ],
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Communications :: Chat',
        'Topic :: Communications :: Chat :: Internet Relay Chat',
    ]
)
