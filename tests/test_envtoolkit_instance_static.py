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
"""Tests for etoolkit.EtoolkitInstance static methods"""
import unittest.mock

import pytest

import etoolkit


@unittest.mock.patch('getpass.getpass')
def test_confirm_password_prompt(getpass, password_hash):
    """Tests the static EtoolkitInstance.confirm_password_prompt method"""
    getpass.return_value = 'The very secret passwd'
    assert (
        etoolkit.EtoolkitInstance.confirm_password_prompt(password_hash)
        == 'The very secret passwd'
    )
    assert (
        etoolkit.EtoolkitInstance.confirm_password_prompt(password_hash, False)
        == 'The very secret passwd'
    )


def test_decrypt():
    """Tests the static EtoolkitInstance.decrypt method"""
    assert (
        etoolkit.EtoolkitInstance.decrypt(
            'The very secret passwd',
            (
                'enc-val$1$/cXpEMoZrTlb9yokGhw8tLTSUkqnqJ4ZoAkurNgMYx'
                'w=$1VdkSMcZnLRwLiu1M8VlYcbelwmiVNY='
            ),
        )
        == 'secret1'
    )

    # now test with modified edata
    with pytest.raises(etoolkit.EtoolkitInstanceError) as exc_info:
        edata = (
            'enc-val$1$/cXpEMoZrTlb9yokGhw8tLTSUkqnqJ5ZoAkurNgMYx'
            'w=$1VdkSMcZnLRwLiu1M8VlYcbelwmiVNY='
        )
        etoolkit.EtoolkitInstance.decrypt(
            'The very secret passwd', edata
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


@unittest.mock.patch('os.urandom')
def test_encrypt_staticly(urandom, non_random_bytes_32):
    """Tests the EtoolkitInstance.encrypt method always with the same salt"""
    urandom.return_value = non_random_bytes_32
    edata = etoolkit.EtoolkitInstance.encrypt('The very secret passwd', 'bar')
    assert edata == (
        'enc-val$1$uYpZM1VfAGq0CDZL2duITs076CQj+hIFEgx+F4mn80'
        'o=$HjPFNv6xC5hbMrFc0L5lSkWdfQ=='
    )
    assert edata == etoolkit.EtoolkitInstance.encrypt(
        'The very secret passwd',
        'bar',
    )


def test_get_new_password_hash():
    """Tests the static EtoolkitInstance.get_new_password_hash method"""
    new_hash = etoolkit.EtoolkitInstance.get_new_password_hash(
        'The very secret passwd'
    )
    # all pbkdf2 params are the same / hardcoded for the time being
    assert new_hash.startswith('pbkdf2_sha256$100000$')
    assert len(new_hash) == 110
    # the hash should always be different because of random salting
    assert new_hash != etoolkit.EtoolkitInstance.get_new_password_hash(
        'The very secret passwd'
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
        'The very secret passwd', password_hash
    )
    assert not etoolkit.EtoolkitInstance.password_matches(
        'The very secret passwdo', password_hash
    )
