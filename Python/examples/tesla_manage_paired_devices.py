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
This example adds a paired device to a Tesla® Powerwall®.

This allows commands requiring authentication to be sent.
"""

# Used to display the keys in Base64.
import base64

# This script makes heavy use of JSON parsing.
import json

# We compare against the epoch time.
import time

# All the shared Tesla® API functions are in this package.
from tesla_api.cloud.authentication import Authentication
from tesla_api.cloud.owner_api import OwnerAPI

# We perform cryptographic operations.
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


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

        # https://developer.tesla.com/docs/fleet-api/authentication/third-party-tokens
        # https://techdocs.akamai.com/identity-cloud/docs/modify-token-lifetimes
        'refresh_expiry': time.time() + 7776000
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

    # Instantiate the Tesla® API wrapper.
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
        # Get a JWT from our Tesla® login.
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
        raise ValueError('Unable to process Tesla® products response.')

    # Take each product.
    for product in response['response']:
        # Is this product an energy product.
        if 'energy_site_id' in product:
            # Add to the list.
            result.append(product['energy_site_id'])

    # Return the resulting list of energy site IDs.
    return result

def get_or_update_tesla_energy_site_id(configuration, owner_api):
    # Get a reference to the 'tesla' section of the configuration.
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

def main():
    """
    Main function for managing Telsa Powerwall® paired devices.

    This function loads credentials from a JSON file, initializes a session with Tesla® Owner API
    generates cryptographic keys, shares the public one with Tesla® so that authenticated commands
    can be sent.

    Args:
        None

    Returns:
        None
    """

    # Load configuration.
    with open('configuration/credentials.json', mode='r+', encoding='utf-8') as json_file:
        configuration = json.load(json_file)

    if 'paired_device' in configuration.get('tesla', {}):
        raise ValueError('You already have device pairing information in the configuration.\n'
                         'To prevent overwriting an existing pairing this program will not continue.\n'
                         'Please delete the paired_device from the configuration to attempt to re-pair again.'
                         )

    # Get an authenticated instance of the Tesla® Owner API.
    owner_api = get_tesla_api_session(configuration)

    # Get the energy site ID.
    energy_site_id = get_or_update_tesla_energy_site_id(configuration, owner_api)

    # Generate a paired device key pair.
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    base64_private_key = base64.b64encode(private_key_bytes).decode('utf-8')
    print(f'Private Key:\n{base64_private_key}\n')

    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1
    )
    base64_public_key = base64.b64encode(public_key_bytes).decode('utf-8')
    print(f'Public Key:\n{base64_public_key}\n')

    # Add the paired_device information in the configuration.
    configuration['tesla']['paired_device'] = {
        'private_key': base64_private_key,
        'public_key': base64_public_key
    }

    # Update the file to include the new paired_device.
    with open('configuration/credentials.json', mode='w', encoding='utf-8') as json_file:
        json.dump(configuration, json_file, indent=4)

    # Send the Add Authorized Client Request via Owner API.
    response = owner_api.api_call(
        path=f'/api/1/energy_sites/{energy_site_id}/command?language=en_GB',
        method='POST',
        json={
            'command_properties': {
                'message': {
                    'authorization': {
                        'add_authorized_client_request': {
                            'key_type': 1,
                            'public_key': base64_public_key,
                            'authorized_client_type': 1,
                            'description': 'Tesla-API'
                        }
                    }
                },
                'identifier_type': 1
            },
            'command_type': 'grpc_command'
        }
    )

    # Print out the server's response.
    print(json.dumps(response, indent=4))

    # Inform the user as to what they need to do next.
    print('Please toggle a single Powerwall power switch for Powerwall to accept pairing request.')

    # Repeat for 2 minutes (120 seconds), every 5 seconds = 24 iterations
    for _ in range(24):
        # Send the Add Authorized Client Request via Owner API.
        response = owner_api.api_call(
            path=f'/api/1/energy_sites/{energy_site_id}/command?language=en_GB',
            method='POST',
            json={
                'command_properties': {
                    'message': {
                        'authorization': {
                            'list_authorized_clients_request': {}
                        }
                    },
                    'identifier_type': 1
                },
                'command_type': 'grpc_command'
            }
        )

        # Print out the server's response.
        print(json.dumps(response, indent=4))

        # Wait for 5 seconds before the next iteration.
        time.sleep(5)

# Launch the main method if invoked directly.
if __name__ == '__main__':
    main()
