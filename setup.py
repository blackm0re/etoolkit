# -*- coding: utf-8 -*-

import setuptools

import etoolkit

with open('README.md', 'r', encoding='utf-8') as fh:
    long_description = fh.read()


setuptools.setup(
    name='etoolkit',
    version=etoolkit.__version__,
    author=etoolkit.__author__,
    author_email='sgs@pichove.org',
    description=(
        'A simple toolkit for setting environment variables in a flexible way'
    ),
    license=etoolkit.__license__,
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/blackm0re/etoolkit',
    packages=setuptools.find_packages(),
    exclude_package_data={'': ['.gitignore']},
    entry_points={
        'console_scripts': [
            'etoolkit=etoolkit.__main__:main',
        ],
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        (
            'License :: OSI Approved :: GNU General Public License v3 or later'
            ' (GPLv3+)'
        ),
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: Implementation',
        'Operating System :: POSIX',
        'Topic :: Security :: Cryptography',
    ],
    keywords='unix environment security cryptography',
    project_urls={
        'Bug Reports': 'https://github.com/blackm0re/etoolkit/issues',
        'Source': 'https://github.com/blackm0re/etoolkit',
    },
    install_requires=["cryptography>=3.2"],
    python_requires='>=3.7',
)
