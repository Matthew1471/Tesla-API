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

# We manipulate dates and times.
import datetime

# This script makes heavy use of JSON parsing.
import json

# Text in variables is dedented while still maintaing source code indentation.
import textwrap

# We compare against the epoch time.
import time

# All the shared Tesla® API functions are in this package.
from tesla_api.cloud.authentication import Authentication
from tesla_api.cloud.owner_api import OwnerAPI
from tesla_api.cloud.tariff_content import TariffContent
from tesla_api.cloud.tariff import Tariff

# All the shared Octopus Energy® functions are in this package.
from tesla_api.octopus_energy import OctopusEnergy


def update_octopus_energy_token_configuration(configuration, token_response):
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
    with open('configuration/credentials.json', mode='w', encoding='utf-8') as json_file:
        json.dump(configuration, json_file, indent=4)

    # Return the reference to our new token configuration.
    return token_configuration

def get_octopus_energy_api_session(configuration):
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
    octopus_energy_configuration = configuration.get('octopus_energy', {})

    # Attempt to get a reference to just the token_configuration.
    token_configuration = octopus_energy_configuration.get('token', {})

    # Instantiate the Octopus API wrapper.
    octopus_energy = OctopusEnergy()

    # Attempt to obtain current token.
    current_token = token_configuration.get('current')

    # Do we have a valid JSON Web Token (JWT) to be able to use the service?
    if not (current_token and OctopusEnergy.check_token_valid(current_token)):
        # It is not valid so clear it.
        token_configuration['current'] = None

        # Try refresh token if available and not expired
        refresh_token = token_configuration.get('refresh')
        refresh_expiry = token_configuration.get('refresh_expiry')
        if (refresh_token and refresh_expiry and time.time() < refresh_expiry):
            # Get a JWT from our Octopus refresh token.
            response = (
                octopus_energy.refresh_token(refresh_token)
                .get('data')
                .get('obtainKrakenToken')
            )

            # Update the configuration dictionary, file and reference.
            token_configuration = update_octopus_energy_token_configuration(
                configuration, response
            )

    # Do we still not have a Token?
    if not token_configuration.get('current'):
        api_key = octopus_energy_configuration.get('api_key')
        # Do we have a way to obtain an access token?
        if not api_key:
            # Let the user know why the program is exiting.
            raise ValueError(
                'Unable to login to Octopus Energy® API (missing api_key in credentials.json).'
            )

        # Get a JWT from our Octopus API key.
        response = (
            octopus_energy.get_token_from_api_key(api_key)
            .get('data')
            .get('obtainKrakenToken')
        )

        # Update the configuration dictionary, file and reference.
        token_configuration = update_octopus_energy_token_configuration(
            configuration, response
        )

    # Apply the token to our Octopus API instance.
    octopus_energy.set_token(token_configuration.get('current'))

    # Return the initialised octopus object.
    return octopus_energy

def query_octopus_energy_graphql(octopus_energy, account_number):
    """
    Queries the Octopus Energy® API for the tariff and planned dispatch data.

    Args:
        account_number (str): The Octopus Energy® account number to query.

    Returns:
        dict: JSON response containing the requested data.
    """

    # Build the GetTariffAndPlannedDispatches query.
    query = textwrap.dedent(
        """
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
                          displayName
                          isExport
                          standingCharge
                          tariffCode
                          unitRate
                        }
                        ... on HalfHourlyTariff {
                          displayName
                          isExport
                          standingCharge
                          tariffCode
                          unitRates {
                            value
                            validFrom
                            validTo
                          }
                        }
                        ... on ThreeRateTariff {
                          displayName
                          isExport
                          standingCharge
                          tariffCode
                          dayRate
                          nightRate
                          offPeakRate
                        }
                        ... on DayNightTariff {
                          displayName
                          isExport
                          standingCharge
                          tariffCode
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
        """
    ).strip()
    variables = {'accountNumber': account_number}

    # Request the tariff and planned_dispatches.
    response = octopus_energy.api_call(query, variables)

    # Clean and return the response (there's an excessive amount of nesting otherwise).
    return clean_octopus_energy_response(response.get('data'))

def clean_octopus_energy_response(response):
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

    # For now we do not support multiple properties within an Octopus Energy® account.
    if len(properties) != 1:
        raise ValueError(
            f'{len(properties)} properties are currently under this Octopus Energy® account; '
            'support for this is not currently implemented.'
        )

    # Build a new dictionary that is easier to parse the tariff information.
    result = {'export': {}, 'import': {}}
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

def update_tesla_token_configuration(configuration, token_response):
    """
    Update the Tesla® token configuration and save it to a JSON file.

    This function creates a new token configuration using the provided token response,
    adds it to the main configuration dictionary under the 'tesla' key,
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

    # Create a new Tesla® token_configuration.
    token_configuration = {
        'current': token_response.get('access_token'),
        'refresh': token_response.get('refresh_token'),
        'refresh_expiry': time.time() + token_response.get('expires_in')
    }

    # Add the token_configuration to the configuration
    configuration['tesla']['token'] = token_configuration

    # Update the file to include the modified token.
    with open('configuration/credentials.json', mode='w', encoding='utf-8') as json_file:
        json.dump(configuration, json_file, indent=4)

    # Return the reference to our new token configuration.
    return token_configuration

def get_tesla_api_session(configuration):
    """
    Establishes a session with the Tesla® Owner API.

    This function manages the authentication process to establish a session with Tesla®.

    It initialises the Owner API wrapper for subsequent interactions.

    Args:
        credentials (dict): A dictionary containing the required credentials.

    Returns:
        OwnerAPI: An initialised API wrapper object for interacting with Tesla® Owner API.

    Raises:
        ValueError: If authentication fails or if required credentials are missing.
    """

    # Get a reference just to the tesla_configuration.
    tesla_configuration = configuration.get('tesla', {})

    # Attempt to get a reference to just the token_configuration.
    token_configuration = tesla_configuration.get('token', {})

    # Instantiate the Tesla API wrapper.
    owner_api = OwnerAPI()

    # Attempt to obtain current token.
    current_token = token_configuration.get('current')

    # Do we have a valid JSON Web Token (JWT) to be able to use the service?
    if not (current_token and Authentication.check_token_valid(current_token)):
        # It is not valid so clear it.
        token_configuration['current'] = None

        # Try refresh token if available and not expired
        refresh_token = token_configuration.get('refresh')
        refresh_expiry = token_configuration.get('refresh_expiry')
        if (refresh_token and refresh_expiry and time.time() < refresh_expiry):
            # Get a JWT from our Tesla® refresh token.
            response = Authentication.refresh_token(refresh_token)

            # Update the configuration dictionary, file and reference.
            token_configuration = update_tesla_token_configuration(
                configuration, response
            )

    # Do we still not have a Token?
    if not token_configuration.get('current'):
        # Get a JWT from our Tesla login.
        code_verifier, state = Authentication.authenticate()

        # Ask the user for the code.
        code = None
        while not code:
            user_url = input('Please enter the tesla:// URL that the login page returns after you log in:\n')

            # Attempt to obtain the code.
            code = Authentication.parse_callback(state, user_url)

            # If the code does not match the expected format, tell the user to try again.
            if not code:
                print('Callback is incorrect, please try again.\n\n')

        # Exchange the code for a token.
        response = Authentication.get_token(code, code_verifier)

        # Update the configuration dictionary, file and reference.
        token_configuration = update_tesla_token_configuration(
            configuration, response
        )

    # Apply the token to our Owner API instance.
    owner_api.set_token(token_configuration.get('current'))

    # Return the initialised owner_api object.
    return owner_api

def update_tesla_energy_site_id_configuration(configuration, energy_site_id):
    """
    Update the Tesla® energy site ID configuration and save it to a JSON file.

    This function adds the provided energy_site_id under the 'tesla' key,
    updates the JSON file with the modified configuration.

    Args:
        configuration (dict): The main configuration dictionary to be updated.
        energy_site_id (dict): The selected energy site id.

    Returns:
        None

    Raises:
        IOError: If there is an error while writing to the JSON file.
    """

    # Add or update the energy_site_id in the configuration.
    configuration['tesla']['energy_site_id'] = energy_site_id

    # Update the file to include the modified energy_site_id.
    with open('configuration/credentials.json', mode='w', encoding='utf-8') as json_file:
        json.dump(configuration, json_file, indent=4)

def get_tesla_energy_site_ids(owner_api):
    # Declare an empty list of energy_site_id.
    result = []

    # Query the list of products under the account.
    response = owner_api.api_call('/api/1/products')

    # Can this be parsed.
    if 'response' not in response:
        raise ValueError('Unable to process Tesla products response.')

    # Take each product.
    for product in response['response']:
        # Is this product an energy product.
        if 'energy_site_id' in product:
            # Add to the list.
            result.append(product['energy_site_id'])

    # Return the resulting list of energy site IDs.
    return result

def get_tesla_tou_periods(octopus_tariff, reduce_battery_wear=True):
    # Constants.
    SECONDS_PER_HALF_HOUR = 1800
    HALF_HOUR_PERIODS_PER_DAY = 48

    # If the buy tariff is a StandardTariff then the buy rates are trivial to calculate.
    if octopus_tariff['import']['__typename'] == 'StandardTariff':
        # Convert to pounds.
        fixed_buy_rate = octopus_tariff['import']['unitRate'] / 100

        # Each of the 30 minute slots in 24 hours set to the fixed rate.
        buy_rates = [fixed_buy_rate] * HALF_HOUR_PERIODS_PER_DAY

        # The single unique buy rate in an array.
        sorted_buy_rates = [fixed_buy_rate]
        buy_rates_count = 1
    # If the buy tariff is a half hourly tariff this becomes harder.
    elif octopus_tariff['import']['__typename'] == 'HalfHourlyTariff':
        # Each of the 30 minute slots in 24 hours.
        buy_rates = [None] * HALF_HOUR_PERIODS_PER_DAY

        # Start of the day (midnight).
        now = datetime.datetime.now().astimezone()
        start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)

        # Populate the buy_rates array.
        for unit_rate in octopus_tariff['import']['unitRates']:
            start = datetime.datetime.fromisoformat(unit_rate['validFrom']).astimezone()
            end = datetime.datetime.fromisoformat(unit_rate['validTo']).astimezone()

            # Skip any rates in the past.
            if end < now:
                continue

            # Convert the unitRates' value to pounds.
            buy_rate = unit_rate['value'] / 100

            # Calculate the half-hour slots for start and end.
            start_index = int((start - start_of_day).total_seconds() // SECONDS_PER_HALF_HOUR) % HALF_HOUR_PERIODS_PER_DAY
            end_index = int((end - start_of_day).total_seconds() // SECONDS_PER_HALF_HOUR) % HALF_HOUR_PERIODS_PER_DAY

            # Populate buy_rates, wrapping around if needed (and stopping once 24 hours are filled).
            index = start_index
            while index != end_index and buy_rates[index] is None:
                buy_rates[index] = buy_rate
                index = (index + 1) % HALF_HOUR_PERIODS_PER_DAY

        # Sort unique rates by value (ascending).
        sorted_buy_rates = sorted(set(buy_rates))
        buy_rates_count = len(sorted_buy_rates)
    else:
        raise ValueError(f'{octopus_tariff["import"]["__typename"]} is not a currently implemented import ElectricityTariffType.')

    # Define categories dynamically based on the number of unique rate values.
    categories_map = {
        2: ['OFF_PEAK', 'ON_PEAK'],
        3: ['OFF_PEAK', 'PARTIAL_PEAK', 'ON_PEAK'],
        4: ['SUPER_OFF_PEAK', 'OFF_PEAK', 'PARTIAL_PEAK', 'ON_PEAK']
    }

    # True variable half hourly tariffs will likely have more periods than 4.
    if buy_rates_count > 4:
        # Make up new categories.
        buy_categories = [f'RATE_{i + 1}' for i in range(buy_rates_count)]
    else:
        # Return dictionary with rates to categories mapping.
        buy_categories = categories_map[buy_rates_count]

    buy_categories_to_rates = dict(zip(buy_categories, sorted_buy_rates))
    buy_rates_to_categories = dict(zip(sorted_buy_rates, buy_categories))

    # If the sell tariff is a StandardTariff then the rates are trivial to calculate.
    if octopus_tariff['export']['__typename'] == 'StandardTariff':
        # Convert to pounds.
        fixed_sell_rate = octopus_tariff['export']['unitRate'] / 100

        # Precompute the first key and cheapest buy rate for clarity and efficiency.
        first_key = buy_categories[0]
        cheapest_buy_rate = sorted_buy_rates[0]

        # Reproduce every used buy category but with a fixed sell rate.
        sell_categories_to_rates = {
            # Use a flag to handle the non-cheapest buy rates explicitly when overriding for reduce_battery_wear.
            key: (cheapest_buy_rate if reduce_battery_wear and key != first_key else fixed_sell_rate)
            for key in buy_categories
        }
        sorted_sell_rates = set([cheapest_buy_rate, fixed_sell_rate]) if reduce_battery_wear else set([fixed_sell_rate])
        sell_rates_count = len(buy_categories)
    elif octopus_tariff['export']['__typename'] == 'HalfHourlyTariff':

        # Each of the 30 minute slots in 24 hours.
        sell_rates = [None] * HALF_HOUR_PERIODS_PER_DAY

        # Start of the day (midnight).
        start_of_day = datetime.datetime.now().astimezone().replace(hour=0, minute=0, second=0, microsecond=0)

        # Populate the sell_rates array.
        for unit_rate in octopus_tariff['export']['unitRates']:
            start = datetime.datetime.fromisoformat(unit_rate['validFrom']).astimezone()
            end = datetime.datetime.fromisoformat(unit_rate['validTo']).astimezone()

            # Convert the unitRates' value to pounds.
            sell_rate = unit_rate['value'] / 100

            # Calculate the half-hour slots for start and end.
            start_index = int((start - start_of_day).total_seconds() // SECONDS_PER_HALF_HOUR) % HALF_HOUR_PERIODS_PER_DAY
            end_index = int((end - start_of_day).total_seconds() // SECONDS_PER_HALF_HOUR) % HALF_HOUR_PERIODS_PER_DAY

            # Populate sell_rates, wrapping around if needed (and stopping once 24 hours are filled).
            index = start_index
            while index != end_index and sell_rates[index] is None:
                sell_rates[index] = sell_rate
                index = (index + 1) % HALF_HOUR_PERIODS_PER_DAY

        # Sort unique rates by value (ascending).
        sorted_sell_rates = sorted(set(sell_rates))
        sell_rates_count = len(sorted_sell_rates)

        # If there are more sell rates than buy then sell needs to copy buy.
        # If there are more buy rates than sell then buy needs to copy sell.

    else:
        raise ValueError(f'{octopus_tariff["export"]["__typename"]} is not a currently implemented export ElectricityTariffType.')

    # True variable half hourly tariffs will likely have more periods than 4.
    if sell_rates_count > 4:
        # Make up new categories.
        sell_categories = [f'RATE_{i + 1}' for i in range(sell_rates_count)]
    else:
        # Return dictionary with rates to categories mapping.
        sell_categories = categories_map[sell_rates_count]

    sell_categories_to_rates = dict(zip(sell_categories, sorted_sell_rates))
    sell_rates_to_categories = dict(zip(sorted_sell_rates, sell_categories))

    # Merge the planned_dispatches into the buy_rates.
    for planned_dispatch in octopus_tariff['plannedDispatches']:
        start = datetime.datetime.fromisoformat(planned_dispatch['start']).astimezone()
        end = datetime.datetime.fromisoformat(planned_dispatch['end']).astimezone()

        # The cheapest buy rate.
        buy_rate = sorted_buy_rates[0]

        # Calculate the half-hour slots for start and end.
        start_index = int((start - start_of_day).total_seconds() // SECONDS_PER_HALF_HOUR) % HALF_HOUR_PERIODS_PER_DAY
        end_index = int((end - start_of_day).total_seconds() // SECONDS_PER_HALF_HOUR) % HALF_HOUR_PERIODS_PER_DAY

        # Populate buy_rates, wrapping around if needed.
        index = start_index
        while index != end_index:
            buy_rates[index] = buy_rate
            index = (index + 1) % HALF_HOUR_PERIODS_PER_DAY

    # Start building the Time-Of-Use periods.
    tou_periods = {category: {"periods": []} for category in categories_map[len(sorted_buy_rates)]}

    # Iterate through the rates converting back to time-periods again.
    block_index = 0
    while block_index < HALF_HOUR_PERIODS_PER_DAY:
        current_value = buy_rates[block_index]
        current_category = buy_rates_to_categories[current_value]

        # Find the end of the current block, wrapping around if needed.
        end_index = block_index
        while buy_rates[end_index % HALF_HOUR_PERIODS_PER_DAY] == current_value:
            end_index += 1

        # The first block may not always be the true fromHour and fromMinute but sometimes it is.
        if block_index != 0 or buy_rates[HALF_HOUR_PERIODS_PER_DAY-1] != current_value:
            from_hour, from_minute = divmod(block_index * 30, 60)
            to_hour, to_minute = divmod((end_index % HALF_HOUR_PERIODS_PER_DAY) * 30, 60)

            tou_periods[current_category]["periods"].append({
                "fromDayOfWeek": 0,
                "toDayOfWeek": 6,
                "fromHour": from_hour,
                "fromMinute": from_minute,
                "toHour": to_hour,
                "toMinute": to_minute
            })

        # Move to the next block.
        block_index = end_index

    # Return the tou_periods, buy_categories_to_rates and sell_categories_to_rates.
    return tou_periods, buy_categories_to_rates, sell_categories_to_rates

def get_tesla_tou_settings(octopus_tariff):
    # Generate a new tariff content object to send.
    tariff_content = TariffContent()

    # Calculate the tou_periods and buy/sell rates.
    # We can optionally set the ON_PEAK rate to be the cheapest buy rate to prevent battery wear.
    tou_periods, buy_categories_to_rates, sell_categories_to_rates = get_tesla_tou_periods(octopus_tariff)

    # This is the same for the buy and sell tariffs.
    seasons = {
        "Summer": {
            "fromDay": 1,
            "toDay": 31,
            "fromMonth": 1,
            "toMonth": 12,
            "tou_periods": tou_periods
        }
    }

    # Buy Tariff.
    buy_tariff = Tariff()
    buy_tariff.set_code(octopus_tariff['import']['tariffCode'])
    buy_tariff.set_name(octopus_tariff['import']['displayName'])
    buy_tariff.set_utility('Octopus Energy')
    buy_tariff.set_currency('GBP')
    buy_tariff.set_daily_charges([
        {
            "name": "Standing Charge",
            "amount": octopus_tariff['import']['standingCharge'] / 100
        }
    ])

    # This breaks "Energy Value" impact graph if not set.
    buy_tariff.set_demand_charges({"ALL": { } })

    # Changing the season from "Summer"/"Winter" breaks "Time-of-Use" impact graph.
    buy_tariff.set_energy_charges(
        {
            "Summer": {
                "rates": buy_categories_to_rates
            }
        }
    )
    buy_tariff.set_seasons(seasons)

    # Add the buy Tariff to the tariff_content.
    tariff_content.set_buy_tariff(buy_tariff)

    # Sell Tariff.
    sell_tariff = Tariff()
    sell_tariff.set_code(octopus_tariff['export']['tariffCode'])
    sell_tariff.set_name(octopus_tariff['export']['displayName'])
    sell_tariff.set_utility('Octopus Energy')
    sell_tariff.set_currency('GBP')

    # This breaks the "Energy Value" impact graph if not set.
    sell_tariff.set_demand_charges({"ALL": { } })

    # Changing the season from "Summer"/"Winter" breaks "Time-of-Use" impact graph.
    sell_tariff.set_energy_charges(
        {
            "Summer": {
                "rates": sell_categories_to_rates
            }
        }
    )
    sell_tariff.set_seasons(seasons)

    # Add the export Tariff to the tariff_content.
    tariff_content.set_sell_tariff(sell_tariff)

    # Set the tariff content version.
    tariff_content.set_version(1)

    # Return the time of use settings JSON.
    return {
        'tou_settings': {
            'tariff_content_v2': tariff_content.get_content()
        }
    }

def get_or_update_tesla_energy_site_id(configuration, owner_api):
    # Get a reference to the tesla section of the configuration.
    tesla_configuration = configuration.get('tesla')

    # Save time (and reduce ambiguity) by setting an energy_site_id in the configuration.
    if 'energy_site_id' in tesla_configuration:
        return tesla_configuration.get('energy_site_id')

    # A Tesla® account can contain multiple energy products.
    energy_site_ids = get_tesla_energy_site_ids(owner_api)

    # Print the energy_site_id for the user.
    print('Found Energy Site ID(s): ', end='')
    print(*energy_site_ids, sep=', ')

    # It is undesirable to change TOU settings on an arbitrary site.
    if len(energy_site_ids) != 1:
        raise ValueError(
            f'You have {len(energy_site_ids)} energy products under this account. '
            'You must manually set one to change in the configuration.'
        )

    # Pick the only energy_site_id.
    energy_site_id = energy_site_ids[0]

    # Store the energy_site_id for future use.
    update_tesla_energy_site_id_configuration(configuration, energy_site_id)

    # Return the discovered energy_site_id.
    return energy_site_id

def update_tesla_tariff(owner_api, energy_site_id, time_of_use_settings):
    # Set the time of use settings and return the response.
    return owner_api.api_call(
        path = f'/api/1/energy_sites/{energy_site_id}/time_of_use_settings',
        method = 'POST',
        json = time_of_use_settings
    )

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
    with open('configuration/credentials.json', mode='r+', encoding='utf-8') as json_file:
        configuration = json.load(json_file)

    # Get a reference to the octopus_energy section of the configuration.
    octopus_energy_configuration = configuration.get('octopus_energy')

    # Get an authenticated instance of the API.
    octopus_energy = get_octopus_energy_api_session(configuration)

    # Get the tariff and planned_dispatches.
    octopus_tariff = query_octopus_energy_graphql(
        octopus_energy, octopus_energy_configuration.get('account_number')
    )

    # Print out the Octopus Tariff.
    print('Octopus Tariff:\n\n' + json.dumps(octopus_tariff, indent=4) + '\n')

    # Get the Tesla time of use settings.
    time_of_use_settings = get_tesla_tou_settings(octopus_tariff)

    # Print out the Tesla time of use settings.
    print('Tesla:\n\n' + json.dumps(time_of_use_settings, indent=4))

    # Get an authenticated instance of the API.
    owner_api = get_tesla_api_session(configuration)

    # Get the energy site ID.
    energy_site_id = get_or_update_tesla_energy_site_id(configuration, owner_api)

    # Update Tesla Tariff.
    response = update_tesla_tariff(owner_api, energy_site_id, time_of_use_settings)

    # Print out the server's response.
    print(json.dumps(response, indent=4))

# Launch the main method if invoked directly.
if __name__ == '__main__':
    main()
