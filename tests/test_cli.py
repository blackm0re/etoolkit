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
"""Tests for the CLI (etoolkit.__main__"""
import errno
import os
import unittest.mock

import pytest

import etoolkit
from etoolkit.__main__ import main


@unittest.mock.patch('os.urandom')
@unittest.mock.patch('builtins.input')
def test_decrypt(binput, urandom, capsys, non_random_bytes_32, config_file):
    """Tests encryption via the CLI interface"""
    urandom.return_value = non_random_bytes_32
    binput.return_value = (
        'enc-val$1$uYpZM1VfAGq0CDZL2duITs076CQj+'
        'hIFEgx+F4mn80o=$xdF/1S+R2MGlEQMCOLG6OjEuzw=='
    )
    with unittest.mock.patch.dict(
        os.environ, {'ETOOLKIT_MASTER_PASSWORD': 'the very secret passwd'}
    ):
        with pytest.raises(SystemExit) as exit_info:
            main(['-c', f'{config_file}', '-d'])
        assert exit_info.type == SystemExit
        assert exit_info.value.code == 0
        assert capsys.readouterr().out.strip() == 'Decrypted value: bar'


@unittest.mock.patch('os.urandom')
@unittest.mock.patch('builtins.input', lambda *args: 'bar')
def test_encrypt_with_echo(urandom, capsys, non_random_bytes_32, config_file):
    """Tests encryption via the CLI interface"""
    urandom.return_value = non_random_bytes_32
    with unittest.mock.patch.dict(
        os.environ, {'ETOOLKIT_MASTER_PASSWORD': 'the very secret passwd'}
    ):
        with pytest.raises(SystemExit) as exit_info:
            main(['-c', f'{config_file}', '-e', '-E'])
        assert exit_info.type == SystemExit
        assert exit_info.value.code == 0
        assert capsys.readouterr().out.strip() == (
            'Encrypted value: enc-val$1$uYpZM1VfAGq0CDZL2duITs076CQj+'
            'hIFEgx+F4mn80o=$xdF/1S+R2MGlEQMCOLG6OjEuzw=='
        )


@unittest.mock.patch('os.urandom')
@unittest.mock.patch('getpass.getpass', lambda *args: 'bar')
def test_encrypt_without_echo(gpass, capsys, non_random_bytes_32, config_file):
    """Tests encryption via the CLI interface"""
    gpass.return_value = non_random_bytes_32
    with unittest.mock.patch.dict(
        os.environ, {'ETOOLKIT_MASTER_PASSWORD': 'the very secret passwd'}
    ):
        with pytest.raises(SystemExit) as exit_info:
            main(['-c', f'{config_file}', '-e'])
        assert exit_info.type == SystemExit
        assert exit_info.value.code == 0
        assert capsys.readouterr().out.strip() == (
            'Encrypted value: enc-val$1$uYpZM1VfAGq0CDZL2duITs076CQj+'
            'hIFEgx+F4mn80o=$xdF/1S+R2MGlEQMCOLG6OjEuzw=='
        )


def test_list(capsys, config_file):
    """Tests list via the CLI interface"""
    with pytest.raises(SystemExit) as exit_info:
        main(['-l'])
    assert exit_info.type == SystemExit
    assert exit_info.value.code == errno.EIO
    with pytest.raises(SystemExit) as exit_info:
        main(['-c', f'{config_file}', '-l'])
    assert exit_info.type == SystemExit
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == (
        f'default{os.linesep}dev{os.linesep}secret'
    )


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
    gpass,
    urandom,
    capsys,
    non_random_bytes_32,
):
    """Tests master password hash generation via the CLI interface"""
    urandom.return_value = non_random_bytes_32
    gpass.return_value = 'The very secret passwd'
    with pytest.raises(SystemExit) as exit_info:
        main(['--generate-master-password-hash'])
    assert exit_info.type == SystemExit
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == (
        'Master password hash: pbkdf2_sha256$100000$uYpZM1VfAGq0CDZL2duITs076'
        'CQj+hIFEgx+F4mn80o=$h3PSPLCd37fP15zKdW4CBGn7CXE+q5UiydaF3vbeZHo='
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
