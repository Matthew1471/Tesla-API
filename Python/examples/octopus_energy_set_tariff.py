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
This example provides functionality to interact with the Octopus Energy® API for monitoring
Intelligent Octopus Go dynamic planned dispatch times and then applying them to the Tesla®
Powerwall®.

The functions in this module allow you to:
- Establish an Octopus Energy® API session.
- Fetch dynamic planned dispatch times.
- Generate a Tesla® Powerwall® tariff.
- Apply the tariff to the Tesla® Powerwall®.
"""

 # This script makes heavy use of JSON parsing.
import json

# Text in variables is dedented while still maintaing source code indentation.
import textwrap

# We compare against the epoch time.
import time

# All the shared Octopus Energy® functions are in this package.
from tesla_api.octopus_energy import OctopusEnergy


def update_token_configuration(configuration, token_response):
    """
    Update the Octopus Energy® token configuration and save it to a JSON file.

    This function creates a new token configuration using the provided token response,
    adds it to the main configuration dictionary under the 'octopus_energy' key,
    updates the JSON file with the modified configuration, and returns the reference
    to the new token configuration.

    Args:
        configuration (dict): The main configuration dictionary to be updated.
        token_response (dict): The response containing the new token information.

    Returns:
        dict: The newly created token configuration dictionary.

    Raises:
        IOError: If there is an error while writing to the JSON file.
    """

    # Create a new Octopus Energy® token_configuration.
    token_configuration = {
        'current': token_response.get('token'),
        'refresh': token_response.get('refreshToken'),
        'refresh_expiry': token_response.get('refreshExpiresIn')
    }

    # Add the token_configuration to the configuration
    configuration['octopus_energy']['token'] = token_configuration

    # Update the file to include the modified token.
    with open('configuration/set_tariff.json', mode='w', encoding='utf-8') as json_file:
        json.dump(configuration, json_file, indent=4)

    # Return the reference to our new token configuration.
    return token_configuration

def get_api_session(configuration):
    """
    Establishes a session with the Octopus Energy® API.

    This function manages the authentication process to establish a session with Octopus Energy®.

    It initialises the Octopus API wrapper for subsequent interactions.

    Args:
        credentials (dict): A dictionary containing the required credentials.

    Returns:
        OctopusEnergy: An initialised API wrapper object for interacting with Octopus Energy®.

    Raises:
        ValueError: If authentication fails or if required credentials are missing.
    """

    # Get a reference just to the octopus_energy_configuration.
    octopus_energy_configuration = configuration.get('octopus_energy')

    # Do we have a way to obtain an access token?
    if not octopus_energy_configuration.get('api_key'):
        # Let the user know why the program is exiting.
        raise ValueError(
            'Unable to login to Octopus Energy® API (missing api_key in set_tariff.json).'
        )

    # Instantiate the Octopus API wrapper.
    octopus_energy = OctopusEnergy()

    # Attempt to get a reference to just the token_configuration.
    token_configuration = octopus_energy_configuration.get('token')

    # Do we have a valid JSON Web Token (JWT) to be able to use the service?
    if not (
        token_configuration
        and token_configuration.get('current')
        and OctopusEnergy.check_token_valid(token_configuration['current'])
    ):
        # It is not valid so clear it.
        if token_configuration:
            token_configuration['current'] = None

        # Maybe we can still use an opaque refresh token?
        if (
            token_configuration
            and token_configuration.get('refresh')
            and token_configuration.get('refresh_expiry')
            and time.time() < token_configuration.get('refresh_expiry')
        ):
            # Get a JWT from our Octopus refresh token.
            response = octopus_energy.refresh_token(
                token_configuration['refresh']
            ).get('data').get('obtainKrakenToken')

            # Update the configuration dictionary, file and reference.
            token_configuration = update_token_configuration(configuration, response)

    # Do we still not have a Token?
    if token_configuration is None or not token_configuration.get('current'):
        # Get a JWT from our Octopus API key.
        response = octopus_energy.get_token_from_api_key(
            octopus_energy_configuration['api_key']
        ).get('data').get('obtainKrakenToken')

        # Update the configuration dictionary, file and reference.
        token_configuration = update_token_configuration(configuration, response)

    # Apply the token to our Octopus API instance.
    octopus_energy.set_token(token_configuration.get('current'))

    # Return the initialised octopus object.
    return octopus_energy

def query_graphql(octopus_energy, account_number):
    """
    Queries the Octopus Energy® API for the tariff and planned dispatch data.

    Args:
        account_number (str): The Octopus Energy® account number to query.

    Returns:
        dict: JSON response containing the requested data.
    """

    # Build the GetTariffAndPlannedDispatches query.
    query = textwrap.dedent("""
    query GetTariffAndPlannedDispatches($accountNumber: String!) {
      getTariff: account(accountNumber: $accountNumber) {
        properties {
          electricityMeterPoints {
            meters(includeInactive: false) {
              meterPoint {
                agreements(includeInactive: false, excludeFuture: true) {
                  tariff {
                    __typename
                    ... on StandardTariff {
                      isExport
                      unitRate
                    }
                    ... on HalfHourlyTariff {
                      isExport
                      unitRates {
                        value
                        validFrom
                        validTo
                      }
                    }
                    ... on ThreeRateTariff {
                      isExport
                      dayRate
                      nightRate
                      offPeakRate
                    }
                    ... on DayNightTariff {
                      isExport
                      dayRate
                      nightRate
                    }
                  }
                }
              }
            }
          }
        }
      }
      getPlannedDispatches: plannedDispatches(accountNumber: $accountNumber) {
        start
        end
        delta
        meta {
          source
        }
      }
    }
    """).strip()
    variables = {'accountNumber': account_number}

    # Request the tariff and planned_dispatches.
    response = octopus_energy.api_call(query, variables)

    # Clean response (there's an excessive amount of nesting otherwise).
    response = clean_response(response.get('data'))

    # Return the data.
    return response

def clean_response(response):
    """
    Reformats the dictionary data into something more easily iterable.

    Args:
        response (dict): The data following the Octopus Energy® GraphQL™ JSON format.

    Returns:
        dict: Dictionary containing the requested data in a easier format.

    Raises:
        ValueError:
            If Octopus Energy® contains multiple properties.
            As support for this is not currently implemented.
    """
    properties = response.get('getTariff').get('properties')

    # For now we do not support multiple properties within an Octopus Energy account.
    if len(properties) != 1:
        raise ValueError(
            f'{len(properties)} properties are currently under this Octopus Energy® account; '
            'support for this is not currently implemented.'
        )

    # Build a new dictionary that is easier to parse the tariff information.
    result = { 'export': {}, 'import': {} }
    electricity_meter_points = properties[0].get('electricityMeterPoints')
    for electricity_meter_point in electricity_meter_points:
        for meter in electricity_meter_point.get('meters'):
            for agreement in meter.get('meterPoint').get('agreements'):
                tariff = agreement.get('tariff')

                if tariff.get('isExport'):
                    result['export'] = tariff
                else:
                    result['import'] = tariff

                # Remove the isExport key once it has been handled.
                del tariff['isExport']

    # Add the plannedDispatches information to our new dictionary.
    result['plannedDispatches'] = response.get('getPlannedDispatches')

    # Return the new dictionary.
    return result

def main():
    """
    Main function for collecting and displaying Octopus Energy® Intelligent dynamic times.

    This function loads credentials from a JSON file, initializes a session with Octopus Energy®
    API, retrieves the device planned dispatches (dynamic times), and displays the information on
    the console.

    Args:
        None

    Returns:
        None
    """

    # Load configuration.
    with open('configuration/set_tariff.json', mode='r+', encoding='utf-8') as json_file:
        configuration = json.load(json_file)

    # Get a reference to the octopus_energy section of the configuration.
    octopus_energy_configuration = configuration.get('octopus_energy')

    # Get an authenticated instance of the API.
    octopus_energy = get_api_session(configuration)

    # Get the tariff and planned_dispatches.
    response = query_graphql(octopus_energy, octopus_energy_configuration.get('account_number'))

    # Print out the new dictionary.
    print(json.dumps(response, indent=4))

# Launch the main method if invoked directly.
if __name__ == '__main__':
    main()
