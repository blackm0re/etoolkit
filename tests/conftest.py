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
                'pbkdf2_sha256$100000$uYpZM1VfAGq0CDZL2duITs076CQj+hIFEgx+F4m'
                'n80o=$h3PSPLCd37fP15zKdW4CBGn7CXE+q5UiydaF3vbeZHo='
            )
        },
        'instances': {
            '_default': {
                'ETOOLKIT_PROMPT': '(%i)',
                'PYTHONPATH': '/home/foo/%i/python',
            },
            'dev': {
                'ETOOLKIT_PARENT': '_default',
                'PYTHONPATH': '%p:/home/user/%i/.pythonpath',
            },
            'secret': {
                'ETOOLKIT_PARENT': '_default',
                'ETOOLKIT_SENSITIVE': ['PASSWORD'],
                'GNUPGHOME': '%h/private/.gnupg',
                'PASSWORD': (
                    'enc-val$1$vIBcoCNiYrsDLtF41uLuSEnppBjhliD0B8jwcBJcj/c=$Kw'
                    'OGe/y1dlxktDaCnJPIVNuaQ4Q7yNo='
                ),
            },
        },
    }


@pytest.fixture()
def config_file(tmp_path, config_data):
    """temporary config file for testing that includes config_data"""

    cf = tmp_path / 'etoolkit.json'
    cf.write_text(json.dumps(config_data))
    return str(cf)


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
        'pbkdf2_sha256$100000$uYpZM1VfAGq0CDZL2duITs076CQj+hIFEgx+F4mn80o=$h3'
        'PSPLCd37fP15zKdW4CBGn7CXE+q5UiydaF3vbeZHo='
    )
