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
"""Tests for the CLI (etoolkit.__main__"""
import pytest

import etoolkit
from etoolkit.__main__ import main


def test_help(capsys):
    """Dummy test checking if the CLI is available at all"""
    with pytest.raises(SystemExit) as exit_info:
        main(['-h'])
    assert exit_info.type == SystemExit
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.startswith('usage: etoolkit')


def test_version(capsys):
    """Dummy test checking if the CLI is available at all"""
    with pytest.raises(SystemExit) as exit_info:
        main(['-v'])
    assert exit_info.type == SystemExit
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.startswith(
        f'etoolkit {etoolkit.__version__}'
    )
