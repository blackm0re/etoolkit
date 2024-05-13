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
"""Tests for etoolkit.EtoolkitInstance"""

import pytest

import etoolkit


def test_instantiation(config_data):
    """Tests for object instatiation"""

    with pytest.raises(etoolkit.EtoolkitInstanceError) as exc_info:
        instance = etoolkit.EtoolkitInstance('devv', config_data)
    assert exc_info.type is etoolkit.EtoolkitInstanceError
    assert exc_info.value.args[0] == 'Unknown instance "devv"'

    instance = etoolkit.EtoolkitInstance('secret', config_data)
    assert 'ETOOLKIT_PARENT' not in instance.raw_env_variables
    assert 'ETOOLKIT_SENSITIVE' not in instance.raw_env_variables
    assert 'DB_CONNECTION' not in instance.sensitive_env_variables
    assert 'ETOOLKIT_TEST_PASSWORD' in instance.sensitive_env_variables
    assert instance.name == 'secret'
    assert (
        instance.master_password_hash
        == (config_data['general']['MASTER_PASSWORD_HASH'])
    )
    assert instance.master_password is None


def test_get_environ(
    config_data, master_password, short_value, wrong_master_password
):
    """Tests the EtoolkitInstance.get_environ method"""

    instance = etoolkit.EtoolkitInstance('secret', config_data)
    with pytest.raises(etoolkit.EtoolkitInstanceError) as exc_info:
        env = instance.get_environ()
    assert exc_info.type is etoolkit.EtoolkitInstanceError
    assert exc_info.value.args[0] == 'Neither password or prompt function set'

    instance.master_password = wrong_master_password
    with pytest.raises(etoolkit.EtoolkitInstanceError) as exc_info:
        env = instance.get_environ()
    assert exc_info.type is etoolkit.EtoolkitInstanceError
    assert exc_info.value.args[0].startswith(
        'Invalid tag when decrypting: enc-val$'
    )

    instance.master_password = master_password
    env = instance.get_environ()
    assert isinstance(env, dict)
    assert env['ETOOLKIT_TEST_PASSWORD'] == short_value


def test_get_full_name(config_data):
    """Tests the EtoolkitInstance.get_full_name method"""

    instance = etoolkit.EtoolkitInstance('secret', config_data)
    assert instance.get_full_name('->') == '_default->secret'


def test_parent_vars(config_data):
    """Tests the EtoolkitInstance.get_full_name method"""

    instance = etoolkit.EtoolkitInstance('dev', config_data)
    assert instance.get_full_name('->') == '_default->dev'
    assert instance.get_environ()['ETOOLKIT_TEST_PYTHONPATH'] == (
        '/home/foo/_default/python:/home/user/dev/.pythonpath'
    )
