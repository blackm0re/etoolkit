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
"""Tests for etoolkit.EtoolkitInstance static methods"""

import unittest.mock

import pytest

import etoolkit


@unittest.mock.patch('getpass.getpass')
def test_confirm_password_prompt(getpass, password_hash, master_password):
    """Tests the static EtoolkitInstance.confirm_password_prompt method"""

    getpass.return_value = master_password
    assert (
        etoolkit.EtoolkitInstance.confirm_password_prompt(password_hash)
        == master_password
    )
    assert (
        etoolkit.EtoolkitInstance.confirm_password_prompt(password_hash, False)
        == master_password
    )


def test_decrypt_v1(master_password, short_encrypted_value_v1, short_value):
    """Tests the static EtoolkitInstance.decrypt method"""

    assert (
        etoolkit.EtoolkitInstance.decrypt(
            master_password, short_encrypted_value_v1
        )
        == short_value
    )

    # now test with modified edata
    edata = (
        'enc-val$1$/cXpEMoZrTlb9yokGhw8tLTSUkqnqJ5ZoAkurNgMYx'
        'w=$1VdkSMcZnLRwLiu1M8VlYcbelwmiVNY='
    )
    with pytest.raises(etoolkit.EtoolkitInstanceError) as exc_info:
        etoolkit.EtoolkitInstance.decrypt(master_password, edata)
    assert exc_info.type is etoolkit.EtoolkitInstanceError
    assert exc_info.value.args[0] == f'Invalid tag when decrypting: {edata}'


def test_decrypt_v2_no_padding(
    master_password, long_encrypted_value, long_value
):
    """Tests the static EtoolkitInstance.decrypt method for v2 - no padding"""

    assert (
        etoolkit.EtoolkitInstance.decrypt(
            master_password, long_encrypted_value
        )
        == long_value
    )

    # now test with modified encrypted data
    edata = long_encrypted_value[:60] + '5' + long_encrypted_value[61:]

    with pytest.raises(etoolkit.EtoolkitInstanceError) as exc_info:
        etoolkit.EtoolkitInstance.decrypt(master_password, edata)
    assert exc_info.type is etoolkit.EtoolkitInstanceError
    assert exc_info.value.args[0] == f'Invalid tag when decrypting: {edata}'


def test_decrypt_v2_with_padding(
    master_password, short_encrypted_value, short_value
):
    """Tests the static EtoolkitInstance.decrypt method for v2 with padding"""

    assert (
        etoolkit.EtoolkitInstance.decrypt(
            master_password, short_encrypted_value
        )
        == short_value
    )

    # now test with modified edata
    edata = short_encrypted_value[:60] + '5' + short_encrypted_value[61:]
    with pytest.raises(etoolkit.EtoolkitInstanceError) as exc_info:
        etoolkit.EtoolkitInstance.decrypt(master_password, edata)
    assert exc_info.type is etoolkit.EtoolkitInstanceError
    assert exc_info.value.args[0] == f'Invalid tag when decrypting: {edata}'


def test_encrypt_no_padding(master_password, long_value):
    """Tests the static EtoolkitInstance.encrypt method with a long string"""

    edata = etoolkit.EtoolkitInstance.encrypt(master_password, long_value)
    assert edata.startswith('enc-val$2$')
    assert len(edata) == 131
    # the edata should always be different because of random salting
    assert edata != etoolkit.EtoolkitInstance.encrypt(
        master_password, long_value
    )


def test_encrypt_with_padding(master_password, short_value):
    """Tests the static EtoolkitInstance.encrypt method with a short string"""

    edata = etoolkit.EtoolkitInstance.encrypt(master_password, short_value)
    assert edata.startswith('enc-val$2$')
    assert len(edata) == 123
    # the edata should always be different because of random salting
    assert edata != etoolkit.EtoolkitInstance.encrypt(
        master_password, short_value
    )


@unittest.mock.patch('os.urandom')
def test_encrypt_staticly_no_padding(
    urandom,
    master_password,
    non_random_bytes_32,
    long_encrypted_value,
    long_value,
):
    """Tests the EtoolkitInstance.encrypt method always with the same salt"""

    urandom.return_value = non_random_bytes_32
    edata = etoolkit.EtoolkitInstance.encrypt(master_password, long_value)
    assert edata == long_encrypted_value
    assert len(edata) == 131
    assert edata == etoolkit.EtoolkitInstance.encrypt(
        master_password, long_value
    )


@unittest.mock.patch('os.urandom')
def test_encrypt_staticly_with_padding(
    urandom,
    master_password,
    non_random_bytes_57,
    short_encrypted_value,
    short_value,
):
    """Tests the EtoolkitInstance.encrypt method always with the same salt"""

    urandom.return_value = non_random_bytes_57
    edata = etoolkit.EtoolkitInstance.encrypt(master_password, short_value)
    assert edata == short_encrypted_value
    assert edata == etoolkit.EtoolkitInstance.encrypt(
        master_password, short_value
    )


def test_get_new_password_hash(master_password):
    """Tests the static EtoolkitInstance.get_new_password_hash method"""

    new_hash = etoolkit.EtoolkitInstance.get_new_password_hash(master_password)
    # all pbkdf2 params are the same / hardcoded for the time being
    assert new_hash.startswith('pbkdf2_sha256$500000$')
    assert len(new_hash) == 110
    # the hash should always be different because of random salting
    assert new_hash != etoolkit.EtoolkitInstance.get_new_password_hash(
        master_password
    )


def test_parse_value():
    """Tests the static EtoolkitInstance.parse_value method"""

    assert (
        etoolkit.EtoolkitInstance.parse_value('t%bs%t', {'%b': 'e', '%t': 't'})
        == 'test'
    )


def test_password_matches(
    password_hash, master_password, wrong_master_password
):
    """Tests the static EtoolkitInstance.password_matches method"""

    assert etoolkit.EtoolkitInstance.password_matches(
        master_password, password_hash
    )
    assert not etoolkit.EtoolkitInstance.password_matches(
        wrong_master_password, password_hash
    )


@unittest.mock.patch('os.urandom')
def test_reencrypt_staticly_with_padding(
    urandom,
    master_password,
    new_master_password,
    non_random_bytes_57,
    short_encrypted_value,
    short_encrypted_value_v1,
    short_value,
):
    """Tests the EtoolkitInstance.reencrypt method always with the same salt"""

    urandom.return_value = non_random_bytes_57
    # reencrypt (migrate) v1 to current using the same password
    edata = etoolkit.EtoolkitInstance.reencrypt(
        master_password, master_password, short_encrypted_value_v1
    )
    assert edata == short_encrypted_value

    # same version, same salt, same edata
    assert edata == etoolkit.EtoolkitInstance.reencrypt(
        master_password, master_password, edata
    )

    # use different password
    edata = etoolkit.EtoolkitInstance.reencrypt(
        master_password, new_master_password, edata
    )
    assert edata != short_encrypted_value
    assert (
        etoolkit.EtoolkitInstance.decrypt(new_master_password, edata)
        == short_value
    )
