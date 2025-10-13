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
Tesla-API Tariff Module
This module provides classes and methods for representing a tariff in the Tesla® API.
"""

# This script makes heavy use of JSON parsing.
import json


class Tariff:
    """
    A class to represent a single energy tariff in the Tesla® API.
    This supports being output as a JSON string directly.
    """

    def __init__(self):
        """
        Initialize a Tariff instance.
        """

        # The tariff_content.
        self.content = {}

    def __str__(self):
        # Return the content dictionary as JSON.
        return json.dumps(self.content, indent=2)

    def get_content(self):
        return self.content

    def set_monthly_minimum_bill(self, monthly_minimum_bill):
        """
        Sets the monthly minimum bill.

        This method sets the minimum bill amount that a customer must pay each month, regardless of their actual energy usage.
        It's a common feature in energy tariffs to ensure a baseline revenue for the provider.

        Args:
            monthly_minimum_bill (uint): The minimum monthly charge for this tariff.

        Returns:
            None
        """
        self.content['monthly_minimum_bill'] = monthly_minimum_bill

    def set_min_applicable_demand(self, min_applicable_demand):
        """
        Sets the minimum applicable demand value.

        This method sets the minimum amount of usage that a customer must pay for each month, regardless of their actual energy usage.
        
        These are not common for residential systems.

        Args:
            min_applicable_demand (uint): The minimum amount of demand on this tariff.

        Returns:
            None
        """
        self.content['min_applicable_demand'] = min_applicable_demand

    def set_max_applicable_demand(self, max_applicable_demand):
        """
        Sets the maximum applicable demand value.

        This method sets the maximum amount of usage that a customer can use each month on this tariff.
        Exceeding this may incur additional fees.
        
        These are not common for residential systems.

        Args:
            max_applicable_demand (uint): The maximum amount of demand allowed on this tariff.

        Returns:
            None
        """
        self.content['max_applicable_demand'] = max_applicable_demand

    def set_monthly_charges(self, monthly_charges):
        """
        Sets the monthly charges.

        The monthly charges for this tariff.

        Args:
            monthly_charges (uint): The monthly charge for this tariff.

        Returns:
            None
        """
        self.content['monthly_charges'] = monthly_charges

    def set_utility(self, utility):
        """
        Sets the utility company name.

        The name of the utility company providing this tariff.

        Args:
            utility (str): The utility company name.

        Returns:
            None
        """
        self.content['utility'] = utility

    def set_code(self, code):
        """
        Sets the utility company tariff code.

        The utility company's tariff code.

        Args:
            code (str): The utility company tariff code.

        Returns:
            None
        """
        self.content['code'] = code

    def set_name(self, name):
        """
        Sets the utility company tariff name.

        The utility company's tariff name.

        Args:
            name (str): The utility company tariff name.

        Returns:
            None
        """
        self.content['name'] = name

    def set_currency(self, currency):
        """
        Sets the currency.

        The currency the pricing units are in.
        The following are valid currency strings: USD, EUR, GBP

        Args:
            currency (str): The unit price currency.

        Returns:
            None
        """
        valid_currencies = ['USD', 'EUR', 'GBP', '']
        if currency not in valid_currencies:
            raise ValueError(f'Invalid currency "{currency}". Valid options are: {valid_currencies}')

        self.content['currency'] = currency

    def set_daily_charges(self, daily_charges):
        """
        Sets the daily charges.

        Most tariffs have a daily charge or standing cost for being on a tariff.

        Example:
            [{ "name": "Charge", "amount": 0 }]

        Args:
            daily_charges (array): The daily charges.

        Returns:
            None
        """
        self.content['daily_charges'] = daily_charges

    def set_daily_demand_charges(self, daily_demand_charges):
        """
        Sets the daily demand charges.

        Demand charges are on some tariffs that charge a fee for peak power consumption.
        These are not common for residential systems.

        Example:
            {}

        Args:
            daily_demand_charges (dict): The daily demand charges.

        Returns:
            None
        """
        self.content['daily_demand_charges'] = daily_demand_charges

    def set_demand_charges(self, demand_charges):
        """
        Sets the demand charges.

        Demand charges are on some tariffs that charge a fee for peak power consumption.
        These are not common for residential systems.

        Prices in ALL apply to all time periods.
        It is recommended to use the ALL field for flat/fixed tariffs instead of creating tariff periods.

        Example:
            { "ALL": { "rates": { "ALL": 0 } }, "Summer": { "rates": {} }, "Winter": { "rates": {} } }

        Args:
            demand_charges (dict): The demand charges per season.

        Returns:
            None
        """
        self.content['demand_charges'] = demand_charges

    def set_energy_charges(self, energy_charges):
        """
        Sets the energy charges.

        Energy charges are usually per kWh and are often known as the unit rate.
        On a time of use tariff different periods can have different unit rates.
        
        Prices in ALL apply to all time periods.
        It is recommended to use the ALL field for flat/fixed tariffs instead of creating tariff periods.

        Example:
            {
                "ALL": { 
                    "rates": { "ALL": 0 }
                },
                "Summer": {
                    "rates": { "PARTIAL_PEAK": 0.4138, "ON_PEAK": 0.4305, "OFF_PEAK": 0.2451 }
                },
                "Winter": {
                    "rates": { "PARTIAL_PEAK": 0.4471, "ON_PEAK": 0.5576, "OFF_PEAK": 0.2451 }
                }
            }

        Args:
            energy_charges (dict): The unit charges for the different seasons and periods.

        Returns:
            None
        """
        self.content['energy_charges'] = energy_charges

    def set_seasons(self, seasons):
        """
        Sets the seasons.

        Each season contains a tariff period specifying the start and end months/days along with its time of use periods.
        Seasons can have arbitrary names as they are just a way to distinguish rates for specific times of the year.
        At least one season must be present.

        Example:
             {
                "Summer": {
                    "toDay": 31,
                    "fromDay": 1,
                    "tou_periods": {
                        "PARTIAL_PEAK": {
                            "periods": [
                                { "fromDayOfWeek": 0, "toHour": 16, "toDayOfWeek": 6, "fromHour": 15, "fromMinute": 0, "toMinute": 0 },
                                { "fromDayOfWeek": 0, "toHour": 0, "toDayOfWeek": 6, "fromHour": 21, "fromMinute": 0, "toMinute": 0 }
                            ]
                        },
                        "ON_PEAK": {
                            "periods": [
                                { "fromDayOfWeek": 0, "toHour": 21, "toDayOfWeek": 6, "fromHour": 16, "fromMinute": 0, "toMinute": 0 }
                            ]
                        },
                        "OFF_PEAK": {
                            "periods": [
                                { "fromDayOfWeek": 0, "toHour": 15, "toDayOfWeek": 6, "fromHour": 0, "fromMinute": 0, "toMinute": 0 }
                            ]
                        }
                    },
                    "toMonth": 5,
                    "fromMonth": 10
                },
                "Winter": {
                    "toDay": 30,
                    "fromDay": 1,
                    "tou_periods": {
                        "PARTIAL_PEAK": {
                            "periods": [
                                { "fromDayOfWeek": 0, "toHour": 16, "toDayOfWeek": 6, "fromHour": 15, "fromMinute": 0, "toMinute": 0 },
                                { "fromDayOfWeek": 0, "toHour": 0, "toDayOfWeek": 6, "fromHour": 21, "fromMinute": 0, "toMinute": 0 }
                            ]
                        },
                        "ON_PEAK": {
                            "periods": [
                                { "fromDayOfWeek": 0, "toHour": 21, "toDayOfWeek": 6, "fromHour": 16, "fromMinute": 0, "toMinute": 0 }
                            ]
                        },
                        "OFF_PEAK": {
                            "periods": [
                                { "fromDayOfWeek": 0, "toHour": 15, "toDayOfWeek": 6, "fromHour": 0, "fromMinute": 0, "toMinute": 0 }
                            ]
                        }
                    },
                    "toMonth": 9,
                    "fromMonth": 6
                   }
                }
             }

        Args:
            seasons (dict): The seasons and their time of use periods.

        Returns:
            None
        """
        self.content['seasons'] = seasons
