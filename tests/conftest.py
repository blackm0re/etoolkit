# etoolkit
# Copyright (C) 2021-2024 Simeon Simeonov

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""Common fixtures"""

import json

import pytest


@pytest.fixture()
def config_data():
    """config_data for testing"""

    return {
        'general': {
            'MASTER_PASSWORD_HASH': (
                'pbkdf2_sha256$500000$UY3o78KUM1Btzxk3k3JCsijnwtJ2lx+hH9Newp'
                'VKxo8=$tHwDm8OVKanC4DoYTigTCb0R3lQIa/CbBYj0B3TZtHg='
            )
        },
        'instances': {
            '_default': {
                'ETOOLKIT_PROMPT': '(%i)',
                'ETOOLKIT_TEST_PYTHONPATH': '/home/foo/%i/python',
            },
            'dev': {
                'ETOOLKIT_PARENT': '_default',
                'ETOOLKIT_TEST_PYTHONPATH': '%p:/home/user/%i/.pythonpath',
            },
            'secret': {
                'ETOOLKIT_PARENT': '_default',
                'ETOOLKIT_SENSITIVE': ['ETOOLKIT_TEST_PASSWORD'],
                'GNUPGHOME': '%h/private/.gnupg',
                'ETOOLKIT_TEST_PASSWORD': (
                    'enc-val$2$v6F2M7LeUDbQWNLg6WW5mUcbuYYo7aGynSxzWAENVBI=$'
                    'ZcyWzf9Kp0aYI8N+biKMSmu4RGGi199ayq'
                    'EYdJl+qdq7b1HSutwYlC7UR2GsSofu4Xo='
                ),
            },
        },
    }


@pytest.fixture()
def config_file(tmp_path, config_data):
    """Temporary config file for testing that includes config_data"""

    cf = tmp_path / 'etoolkit.json'
    cf.write_text(json.dumps(config_data))
    return str(cf)


@pytest.fixture()
def master_password():
    """Master passord"""
    return 'The very secret passwd'


@pytest.fixture()
def non_random_bytes_32():
    """always use the same bytes instead of os.urandom(32)"""

    return (
        b'\xb9\x8aY3U_\x00j\xb4\x086K\xd9\xdb\x88N'
        b'\xcd;\xe8$#\xfa\x12\x05\x12\x0c~\x17\x89\xa7\xf3J'
    )


@pytest.fixture()
def non_random_bytes_61():
    """always use the same bytes instead of os.urandom(61)"""

    return (
        b'D$\x99\xaa\xafiZ\xb4C\xa0%XTz)\xca\xedK\xcd\xa2F~\xff+\xa1[\xe2\xaa'
        b'\xb2\xd3\x07\x13\xedb\xc2\x84\xfe\tS\r\xf0\x02_\xef\xe3\xde\xf1?e'
        b'\xa4s(Q\x04\xcd\xc7T\x01_D\xb1'
    )


@pytest.fixture()
def nonexistent_config_file(tmp_path):
    """temporary config file for testing that includes config_data"""

    return str(tmp_path / 'etoolkitt.json')


@pytest.fixture()
def password_hash():
    """password hash for testing, corresponding to 'The very secret passwd'"""

    return (
        'pbkdf2_sha256$500000$UY3o78KUM1Btzxk3k3JCsijnwtJ2lx+hH9NewpVKxo8=$'
        'tHwDm8OVKanC4DoYTigTCb0R3lQIa/CbBYj0B3TZtHg='
    )


@pytest.fixture()
def wrong_master_password():
    """Wrong master passord"""
    return 'the very secret passwd'
