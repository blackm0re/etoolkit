# etoolkit
# Copyright (C) 2021 Simeon Simeonov

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
import pytest


@pytest.fixture
def config_data():
    """config_data for testing"""
    return {
        'general': {
            'MASTER_PASSWORD_HASH': (
                'pbkdf2_sha256$100000$kFOQkAPtStZ/Ny/O4501ygHGQnqh5Y+ySxF9qVHr'
                'iv8=$3BujuWzn3CfDnw4yiD9m3F+GjeW1MHHW40R/ThHNcn0='
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
def password_hash():
    """password hash for testing, corresponding to 'the very secret passwd'"""
    return (
        'pbkdf2_sha256$100000$kFOQkAPtStZ/Ny/O4501ygHGQnqh5Y+ySxF9qVHr'
        'iv8=$3BujuWzn3CfDnw4yiD9m3F+GjeW1MHHW40R/ThHNcn0='
    )
