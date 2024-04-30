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


def test_decrypt_v1(master_password):
    """Tests the static EtoolkitInstance.decrypt method"""

    assert (
        etoolkit.EtoolkitInstance.decrypt(
            master_password,
            (
                'enc-val$1$/cXpEMoZrTlb9yokGhw8tLTSUkqnqJ4ZoAkurNgMYx'
                'w=$1VdkSMcZnLRwLiu1M8VlYcbelwmiVNY='
            ),
        )
        == 'secret1'
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


def test_decrypt_v2_no_padding(master_password):
    """Tests the static EtoolkitInstance.decrypt method for v2 - no padding"""

    assert (
        etoolkit.EtoolkitInstance.decrypt(
            master_password,
            (
                'enc-val$2$Wer5lECGyeZhhYS58N18WVx5Zzy+rrC+BPlq3Dw89wQ=$'
                'SQc0ox6Emf2m5rrumsiptpIZEujdpXXSR/'
                '1VcfEZeBz4+KDSagr9ID+bkc4R2yFdxHnhig1eqQ8='
            ),
        )
        == 'Nobody expects the Spanish inquisition'
    )

    # now test with modified edata
    edata = (
        'enc-val$2$Wer5lECGyeZhhYS58N18WVx5Zzy+rrC+BPlq3Dw89wQ=$'
        'SQc0ox6Emf2m4rrumsiptpIZEujdpXXSR/'
        '1VcfEZeBz4+KDSagr9ID+bkc4R2yFdxHnhig1eqQ8='
    )
    with pytest.raises(etoolkit.EtoolkitInstanceError) as exc_info:
        etoolkit.EtoolkitInstance.decrypt(master_password, edata)
    assert exc_info.type is etoolkit.EtoolkitInstanceError
    assert exc_info.value.args[0] == f'Invalid tag when decrypting: {edata}'


def test_decrypt_v2_with_padding(master_password):
    """Tests the static EtoolkitInstance.decrypt method for v2 with padding"""

    assert (
        etoolkit.EtoolkitInstance.decrypt(
            master_password,
            (
                'enc-val$2$//kzyUbDEWNoPC5dyukhB8de8+IVaLR2ngx2HwkfOuM=$'
                'rhRona4wP9nhnXjcHqwkjFDsiVVVjYanAs'
                'N4kknNkgC0ix4RtJQHYDeTzw1rrR1vb2w='
            ),
        )
        == 'secret1'
    )

    # now test with modified edata
    edata = (
        'enc-val$2$//kzyUbDEWNoPC5dyukhB8de8+IVaLR2ngx2HwkfOuM=$'
        'rhRona4wP8nhnXjcHqwkjFDsiVVVjYanAsN4kknNkgC0ix4RtJQHYDeTzw1rrR1vb2w='
    )
    with pytest.raises(etoolkit.EtoolkitInstanceError) as exc_info:
        etoolkit.EtoolkitInstance.decrypt(master_password, edata)
    assert exc_info.type is etoolkit.EtoolkitInstanceError
    assert exc_info.value.args[0] == f'Invalid tag when decrypting: {edata}'


def test_encrypt_no_padding(master_password):
    """Tests the static EtoolkitInstance.encrypt method with a long string"""

    edata = etoolkit.EtoolkitInstance.encrypt(
        master_password, 'Nobody expects the Spanish inquisition'
    )
    assert edata.startswith('enc-val$2$')
    assert len(edata) == 131
    # the edata should always be different because of random salting
    assert edata != etoolkit.EtoolkitInstance.encrypt(
        master_password, 'Nobody expects the Spanish inquisition'
    )


def test_encrypt_with_padding(master_password):
    """Tests the static EtoolkitInstance.encrypt method with a short string"""

    edata = etoolkit.EtoolkitInstance.encrypt(master_password, 'bar')
    assert edata.startswith('enc-val$2$')
    assert len(edata) == 123
    # the edata should always be different because of random salting
    assert edata != etoolkit.EtoolkitInstance.encrypt(master_password, 'bar')


@unittest.mock.patch('os.urandom')
def test_encrypt_staticly_no_padding(
    urandom, master_password, non_random_bytes_32
):
    """Tests the EtoolkitInstance.encrypt method always with the same salt"""

    urandom.return_value = non_random_bytes_32
    edata = etoolkit.EtoolkitInstance.encrypt(
        master_password, 'Nobody expects the Spanish inquisition'
    )
    assert edata == (
        'enc-val$2$uYpZM1VfAGq0CDZL2duITs076CQj+hIFEgx+F4mn80o=$'
        'UX/5YeRsh5/2vZ2J1UOS+BJti73Kbp6C1pJmC'
        'o8hFSujpe35X/XpzAiYv4BV1LNwnSYECsotsgs='
    )
    assert len(edata) == 131
    assert edata == etoolkit.EtoolkitInstance.encrypt(
        master_password, 'Nobody expects the Spanish inquisition'
    )


@unittest.mock.patch('os.urandom')
def test_encrypt_staticly_with_padding(
    urandom, master_password, non_random_bytes_61
):
    """Tests the EtoolkitInstance.encrypt method always with the same salt"""

    urandom.return_value = non_random_bytes_61
    edata = etoolkit.EtoolkitInstance.encrypt(master_password, 'bar')
    assert edata == (
        'enc-val$2$RCSZqq9pWrRDoCVYVHopyu1LzaJGfv8roVviqrLTBxM=$'
        '+Yo6Ya2MAVcBLTQHuATkyFc+dzYsL/ESvA6ofOUDsiKZvIff35cUHAmoNxVuGG+MXv4='
    )
    assert edata == etoolkit.EtoolkitInstance.encrypt(master_password, 'bar')


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
