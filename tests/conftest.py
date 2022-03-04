# etoolkit
# Copyright (C) 2021-2022 Simeon Simeonov

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


@pytest.fixture
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
            'default': {'ETOOLKIT_PROMPT': '(%i)'},
            'dev': {
                'ETOOLKIT_PARENT': 'default',
                'PYTHONPATH': ':/home/user/.pythonpath',
                'DB_CONNECTION': (
                    'enc-val$1$Y/TBb1F3siHTw6qZg9ERzZfA8PLPf2CwGSQLpu9jYWw=$FT'
                    '5tS9o+ABvsxogIXpJim16Gz5SVtV8='
                ),
            },
            'secret': {
                'ETOOLKIT_PARENT': 'default',
                'ETOOLKIT_SENSITIVE': ['PASSWORD'],
                'GNUPGHOME': '%h/private/.gnupg',
                'PASSWORD': (
                    'enc-val$1$vIBcoCNiYrsDLtF41uLuSEnppBjhliD0B8jwcBJcj/c=$Kw'
                    'OGe/y1dlxktDaCnJPIVNuaQ4Q7yNo='
                ),
            },
        },
    }


@pytest.fixture
def config_file(tmp_path, config_data):
    """temporary config file for testing that includes config_data"""
    cf = tmp_path / "etoolkit.json"
    cf.write_text(json.dumps(config_data))
    return str(cf)


@pytest.fixture
def non_random_bytes_32():
    """always use the same bytes instead of os.urandom(32)"""
    return (
        b'\xb9\x8aY3U_\x00j\xb4\x086K\xd9\xdb\x88N'
        b'\xcd;\xe8$#\xfa\x12\x05\x12\x0c~\x17\x89\xa7\xf3J'
    )


@pytest.fixture
def password_hash():
    """password hash for testing, corresponding to 'The very secret passwd'"""
    return (
        'pbkdf2_sha256$100000$uYpZM1VfAGq0CDZL2duITs076CQj+hIFEgx+F4mn80o=$h3'
        'PSPLCd37fP15zKdW4CBGn7CXE+q5UiydaF3vbeZHo='
    )
