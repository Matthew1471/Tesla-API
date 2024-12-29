#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of Tesla-API <https://github.com/Matthew1471/Tesla-API>
# Copyright (C) 2024 Matthew1471!
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
A module for interacting with the Octopus Energy® API.

This module provides functionality to interact with the Octopus Energy® API.
"""

# Allow the user to use OctopusEnergy by just importing tesla_api.octopus_energy.
from .api import OctopusEnergy

# Declare what should be offered in the public API when a wildcard import statement is used.
__all__ = ['OctopusEnergy']
