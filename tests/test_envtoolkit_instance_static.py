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
"""Tests for etoolkit.EtoolkitInstance static methods"""
import unittest.mock

import pytest

import etoolkit


@unittest.mock.patch('getpass.getpass')
def test_confirm_password_prompt(getpass, password_hash):
    """Tests the static EtoolkitInstance.confirm_password_prompt method"""
    getpass.return_value = 'the very secret passwd'
    assert (
        etoolkit.EtoolkitInstance.confirm_password_prompt(password_hash)
        == 'the very secret passwd'
    )
    assert (
        etoolkit.EtoolkitInstance.confirm_password_prompt(password_hash, False)
        == 'the very secret passwd'
    )


def test_decrypt():
    """Tests the static EtoolkitInstance.decrypt method"""
    assert (
        etoolkit.EtoolkitInstance.decrypt(
            'the very secret passwd',
            (
                'enc-val$1$Y/TBb1F3siHTw6qZg9ERzZfA8PLPf2CwGSQLpu9jYWw=$FT5tS9'
                'o+ABvsxogIXpJim16Gz5SVtV8='
            ),
        )
        == 'secret1'
    )

    # now test with modified edata
    with pytest.raises(etoolkit.EtoolkitInstanceError) as exc_info:
        edata = (
            'enc-val$1$Y/TBb1F3siHTw6qZg9ERzZfA8PLPf2CwGSQLpu9jYWw=$FT5tS9'
            'o+ABvsxogIXpJim17Gz5SVtV8='
        )
        etoolkit.EtoolkitInstance.decrypt(
            'the very secret passwd', edata
        ) == 'secret1'
    assert exc_info.type is etoolkit.EtoolkitInstanceError
    assert exc_info.value.args[0] == f'Invalid tag when decrypting: {edata}'


def test_encrypt():
    """Tests the static EtoolkitInstance.encrypt method"""
    edata = etoolkit.EtoolkitInstance.encrypt('foo', 'bar')
    assert edata.startswith('enc-val$')
    assert len(edata) == 83
    # the edata should always be different because of random salting
    assert edata != etoolkit.EtoolkitInstance.encrypt('foo', 'bar')


def test_get_new_password_hash():
    """Tests the static EtoolkitInstance.get_new_password_hash method"""
    new_hash = etoolkit.EtoolkitInstance.get_new_password_hash(
        'the very secret passwd'
    )
    # all pbkdf2 params are the same / hardcoded for the time being
    assert new_hash.startswith('pbkdf2_sha256$100000$')
    assert len(new_hash) == 110
    # the hash should always be different because of random salting
    assert new_hash != etoolkit.EtoolkitInstance.get_new_password_hash(
        'the very secret passwd'
    )


def test_parse_value():
    """Tests the static EtoolkitInstance.parse_value method"""
    assert (
        etoolkit.EtoolkitInstance.parse_value('t%bs%t', {'%b': 'e', '%t': 't'})
        == 'test'
    )


def test_password_matches(password_hash):
    """Tests the static EtoolkitInstance.password_matches method"""
    assert etoolkit.EtoolkitInstance.password_matches(
        'the very secret passwd', password_hash
    )
    assert not etoolkit.EtoolkitInstance.password_matches(
        'the very secret passwdo', password_hash
    )
