#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of Tesla-API <https://github.com/Matthew1471/Tesla-API>
# Copyright (C) 2025 Matthew1471!
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
Tesla-API Tariff Content Module
This module provides classes and methods for representing tariff content in the Tesla® API.
"""

# The tariff specifics are actually in this class.
from .tariff import Tariff

# This script makes heavy use of JSON parsing.
import json


class TariffContent:
    """
    A class to represent a buy (and optional sell) energy tariff in the Tesla® API.
    This supports being output as a string directly.
    """

    # We only support tariff_content_v2.
    VERSION = 2

    def __init__(self):
        """
        Initialize an Tariff Content V2 instance.
        """

        # The Tariff Content.
        self.content = {}

        # The tariffs are declared but set to None by default.
        self.buy_tariff = None
        self.sell_tariff = None

    def get_content(self):
        # The buy tariff is merged into the outer layer.
        if self.content:
            flattened_dictionary = {**self.content, **self.buy_tariff.get_content()}
        else:
            flattened_dictionary = self.buy_tariff.get_content()

        # The sell tariff is under a separate key.
        if self.sell_tariff:
            flattened_dictionary['sell_tariff'] = self.sell_tariff.get_content()

        # Return the result.
        return flattened_dictionary

    def __str__(self):
        # Return the contents as JSON.
        return json.dumps(self.get_content(), indent=2)

    def set_version(self, version):
        self.content['version'] = version

    def set_buy_tariff(self, buy_tariff):
        self.buy_tariff = buy_tariff

    def set_sell_tariff(self, sell_tariff):
        self.sell_tariff = sell_tariff
