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
"""A simple toolkit for setting environment variables in a flexible way"""
from .etoolkit import EtoolkitInstance, EtoolkitInstanceError

__author__ = 'Simeon Simeonov'
__version__ = '1.1.0'
__license__ = 'GPL3'


def int_or_str(value):
    """Returns int value of value when possible"""
    try:
        return int(value)
    except ValueError:
        return value


VERSION = tuple(map(int_or_str, __version__.split('.')))

__all__ = ['EtoolkitInstance', 'EtoolkitInstanceError']
