#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of Tesla-API <https://github.com/Matthew1471/Tesla-API>
# Copyright (C) 2023 Matthew1471!
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
This example provides functionality to interact with the Tesla® Gateway API for monitoring
energy storage, solar energy production and consumption data on the command line.

The functions in this module allow you to:
- Establish a gateway session
- Fetch production, consumption, and storage status from Tesla® Gateway device
- Retrieve human-readable power values
"""

import json # This script makes heavy use of JSON parsing.
import time # We delay between requests.

# All the shared Tesla® functions are in this package.
from tesla_api.local.gateway import Gateway


def get_human_readable_power(watts, in_hours = False):
    """
    Convert power value to a human-readable format.

    Args:
        watts (float):
            Power value in watts.
        in_hours (bool, optional):
            If True, append 'h' to indicate hours. Default is False.

    Returns:
        str:
            Human-readable power value with unit (W or kW).
    """
    # Is the significant number of watts (i.e. positive or negative number) less than a thousand?
    if abs(round(watts)) < 1000:
        # Report the number in watts (rounded to the nearest number).
        return f'{watts:.0f} W{"h" if in_hours else ""}'

    # Divide the number by a thousand and report it in kW (to 2 decimal places).
    return f'{watts/1000:.2f} kW{"h" if in_hours else ""}'

def get_gateway_session(credentials):
    """
    Establishes a session with the Tesla® Gateway API.

    This function manages the authentication process to establish a session with an Tesla®
    Gateway.

    It initialises the Gateway API wrapper for subsequent interactions.

    Args:
        credentials (dict): A dictionary containing the required credentials.

    Returns:
        Gateway: An initialised Gateway API wrapper object for interacting with the gateway.

    Raises:
        ValueError: If authentication fails or if required credentials are missing.
    """

    # Do we have a way to obtain an access token?
    if not credentials.get('gateway_password'):
        # Let the user know why the program is exiting.
        raise ValueError(
            'Unable to login to the gateway (missing credentials in credentials.json).'
        )

    # Did the user override the library default hostname to the Gateway?
    host = credentials.get('gateway_host')

    # Instantiate the Gateway API wrapper (with the default library hostname if None provided).
    gateway = Gateway(host)

    # Are we not able to login to the gateway?
    if not gateway.login(credentials['gateway_password']):
        # Let the user know why the program is exiting.
        raise ValueError('Unable to login to the gateway (bad credentials in credentials.json).')

    # Return the initialised gateway object.
    return gateway

def main():
    """
    Main function for collecting and displaying Tesla® Gateway status.

    This function loads credentials from a JSON file, initializes a session with the Tesla®
    Gateway API, retrieves production and meter statistics, and displays the status information to
    the console.

    Args:
        None

    Returns:
        None
    """

    # Load credentials.
    with open('configuration/credentials.json', mode='r', encoding='utf-8') as json_file:
        credentials = json.load(json_file)

    # Get an instance of the Gateway.
    gateway = get_gateway_session(credentials)

    #More at https://github.com/vloschiavo/powerwall2
    #
    #/api/auth/toggle/supported
    #/api/customer
    #/api/customer/registration
    #/api/devices/vitals
    #/api/logout
    #/api/meters
    #/api/meters/aggregates
    #/api/networks
    #/api/operation
    #/api/powerwalls
    #/api/site_info
    #/api/site_info/site_name
    #/api/sitemaster
    #/api/status
    #/api/system_status
    #/api/system_status/grid_faults
    #/api/system_status/grid_status
    #/api/system_status/soe
    #/api/troubleshooting/problems

    meters = gateway.api_call('/api/meters/aggregates')
    print(meters)

    operation = gateway.api_call('/api/operation')
    print(operation)

    while True:
        # Get the State of Energy.
        status = gateway.api_call('/api/system_status/soe')

        # Output to the console.
        print(f'{Gateway.scale_soe(status["percentage"])} %')

        # Delay 1 second.
        time.sleep(1)

# Launch the main method if invoked directly.
if __name__ == '__main__':
    main()
