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
"""Tests for the CLI (etoolkit.__main__"""

import errno
import os
import unittest.mock

import pytest

import etoolkit
from etoolkit.__main__ import main


@unittest.mock.patch('builtins.input')
def test_decrypt_v1(binput, capsys, config_file, master_password):
    """Tests v1 decryption via the CLI interface"""

    binput.return_value = (
        'enc-val$1$rye0sMGEnd35gOWyISE1FQa6dzS+8/jf6aopMO5tPr4=$'
        'RjnRY0bUJWFOiejTlM3OhKNimQ=='
    )
    with unittest.mock.patch.dict(
        os.environ, {'ETOOLKIT_MASTER_PASSWORD': master_password}
    ):
        with pytest.raises(SystemExit) as exit_info:
            main(['-c', f'{config_file}', '-d'])
        assert exit_info.type == SystemExit
        assert exit_info.value.code == 0
        assert capsys.readouterr().out.strip() == 'Decrypted value: bar'


@unittest.mock.patch('builtins.input')
def test_decrypt_v2(
    binput,
    capsys,
    config_file,
    master_password,
    short_encrypted_value,
    short_value,
):
    """Tests v2 decryption via the CLI interface"""

    binput.return_value = short_encrypted_value
    with unittest.mock.patch.dict(
        os.environ, {'ETOOLKIT_MASTER_PASSWORD': master_password}
    ):
        with pytest.raises(SystemExit) as exit_info:
            main(['-c', f'{config_file}', '-d'])
        assert exit_info.type == SystemExit
        assert exit_info.value.code == 0
        assert capsys.readouterr().out.strip() == (
            f'Decrypted value: {short_value}'
        )


@unittest.mock.patch('os.urandom')
@unittest.mock.patch('builtins.input')
def test_encrypt_with_echo(
    binput,
    urandom,
    capsys,
    non_random_bytes_57,
    config_file,
    master_password,
    short_encrypted_value,
    short_value,
):
    """Tests encryption via the CLI interface"""

    binput.return_value = short_value
    urandom.return_value = non_random_bytes_57
    with unittest.mock.patch.dict(
        os.environ, {'ETOOLKIT_MASTER_PASSWORD': master_password}
    ):
        with pytest.raises(SystemExit) as exit_info:
            main(['-c', f'{config_file}', '-e', '-E'])
        assert exit_info.type == SystemExit
        assert exit_info.value.code == 0
        assert capsys.readouterr().out.strip() == (
            f'Encrypted value: {short_encrypted_value}'
        )


@unittest.mock.patch('os.urandom')
@unittest.mock.patch('getpass.getpass')
def test_encrypt_without_echo(
    getpass,
    urandom,
    capsys,
    non_random_bytes_57,
    config_file,
    master_password,
    short_encrypted_value,
    short_value,
):
    """Tests encryption via the CLI interface"""

    getpass.return_value = short_value
    urandom.return_value = non_random_bytes_57
    with unittest.mock.patch.dict(
        os.environ, {'ETOOLKIT_MASTER_PASSWORD': master_password}
    ):
        with pytest.raises(SystemExit) as exit_info:
            main(['-c', f'{config_file}', '-e'])
        assert exit_info.type == SystemExit
        assert exit_info.value.code == 0
        assert capsys.readouterr().out.strip() == (
            f'Encrypted value: {short_encrypted_value}'
        )


def test_fetch_encrypted_value(config_file, master_password, short_value):
    """Tests decryption of encrypted value"""

    with unittest.mock.patch.dict(
        os.environ, {'ETOOLKIT_MASTER_PASSWORD': master_password}
    ):
        assert os.environ.get('ETOOLKIT_TEST_PASSWORD') is None
        main(['-c', f'{config_file}', '-q', '-s', '/bin/false', 'secret'])
        assert os.environ.get('ETOOLKIT_TEST_PASSWORD') == short_value


def test_list(capsys, config_file, nonexistent_config_file):
    """Tests list via the CLI interface"""

    with pytest.raises(SystemExit) as exit_info:
        main(['-c', nonexistent_config_file, '-l'])
    assert exit_info.type == SystemExit
    assert exit_info.value.code == errno.EIO
    with pytest.raises(SystemExit) as exit_info:
        main(['-c', config_file, '-l'])
    assert exit_info.type == SystemExit
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f'dev{os.linesep}secret'


def test_help(capsys):
    """Dummy test checking if the CLI is available at all"""

    with pytest.raises(SystemExit) as exit_info:
        main(['-h'])
    assert exit_info.type == SystemExit
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.startswith('usage: etoolkit')


@unittest.mock.patch('os.urandom')
@unittest.mock.patch('getpass.getpass')
def test_generate_master_password_hash(
    getpass, urandom, capsys, non_random_bytes_32
):
    """Tests master password hash generation via the CLI interface"""

    getpass.return_value = 'The very secret passwd'
    urandom.return_value = non_random_bytes_32
    with pytest.raises(SystemExit) as exit_info:
        main(['--generate-master-password-hash'])
    assert exit_info.type == SystemExit
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == (
        'Master password hash: pbkdf2_sha256$500000$uYpZM1VfAGq0CDZL2duITs076'
        'CQj+hIFEgx+F4mn80o=$Msl8/5nOBj0TRchykMzXmCXR8VQVyBqUPHe1PDWeJi8='
    )


def test_version(capsys):
    """Dummy test checking if the CLI is available at all"""

    with pytest.raises(SystemExit) as exit_info:
        main(['-v'])
    assert exit_info.type == SystemExit
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.startswith(
        f'etoolkit {etoolkit.__version__}'
    )
