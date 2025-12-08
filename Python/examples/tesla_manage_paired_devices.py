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
This example manages paired devices on a Tesla® Gateway.

This allows commands requiring authentication to be sent.
"""

# We process command line arguments.
import argparse

# Used to display the keys in Base64.
import base64

# This script makes heavy use of JSON parsing.
import json

# Used to convert a time to an expiration time.
import math

# We gracefully exit.
import sys

# We compare against the epoch time.
import time

# We generate unique IDs (uuids).
import uuid

# We perform cryptographic operations.
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# All the protobuf messages and types are in these packages.
from tesla_api.protobuf.energy_device.v1 import (
    authorized_client_type_pb2,
    authorization_api_remove_authorized_client_request_pb2,
    authorization_messages_pb2,
    delivery_channel_pb2,
    message_envelope_pb2,
    participant_pb2
)
from tesla_api.protobuf.signatures import (
    key_identity_pb2,
    rsa_signature_data_pb2,
    signature_data_pb2,
    signature_type_pb2,
    tag_pb2,
)
from tesla_api.protobuf.universal_message.v1 import (
    destination_pb2,
    domain_pb2,
    routable_message_pb2
)

# All the shared Tesla® API functions are in this package.
from tesla_api.cloud.authentication import Authentication
from tesla_api.cloud.owner_api import OwnerAPI


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

def get_or_update_tesla_energy_site_id(configuration, owner_api):
    # Get a reference to the 'tesla' section of the configuration.
    tesla_configuration = configuration.get('tesla')

    # Save time (and reduce ambiguity) by setting an energy_site_id in the configuration.
    if 'energy_site_id' in tesla_configuration:
        return tesla_configuration.get('energy_site_id')

    # A Tesla® account can contain multiple energy products.
    # Query the list of products under the account.
    response = owner_api.api_call('/api/1/products')

    # Can this be parsed.
    if 'response' not in response:
        raise ValueError('Unable to process Tesla® products response.')

    # Collect all "energy_site_id" values from products.
    energy_site_ids = [
        product['energy_site_id']
        for product in response['response']
        if 'energy_site_id' in product
    ]

    # Print the energy_site_id for the user.
    print('Found Energy Site ID(s): ', end='')
    print(*energy_site_ids, sep=', ')

    # It is undesirable to change paired keys on an arbitrary site.
    if len(energy_site_ids) != 1:
        raise ValueError(
            f'You have {len(energy_site_ids)} energy products under this account. '
            'You must manually set one to change in the configuration.'
        )

    # Pick the only energy_site_id.
    energy_site_id = energy_site_ids[0]

    # Store the energy_site_id for future use.
    # Add or update the energy_site_id in the configuration.
    configuration['tesla']['energy_site_id'] = energy_site_id

    # Update the file to include the modified energy_site_id.
    with open('configuration/credentials.json', mode='w', encoding='utf-8') as json_file:
        json.dump(configuration, json_file, indent=4)

    # Return the discovered energy_site_id.
    return energy_site_id

def _list_devices(owner_api, energy_site_id):
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

def to_tlv(tag: int, value_bytes: bytes) -> bytes:
    """
    Encodes a tag and value buffer into a TLV (Tag-Length-Value) byte structure:
    [Tag (1 byte), Length (1 byte), Value (N bytes)].
    """
    # Return the three components in TLV format.
    return tag.to_bytes() + len(value_bytes).to_bytes() + value_bytes

def get_signed_routable_authorization_message(private_key, public_key_bytes, din, authorization_message):
    # Build the MessageEnvelope containing the AuthorizationMessage.
    message_envelope = message_envelope_pb2.MessageEnvelope(
        delivery_channel=delivery_channel_pb2.DELIVERY_CHANNEL_HERMES_COMMAND,
        sender=participant_pb2.Participant(
            authorized_client=authorized_client_type_pb2.AUTHORIZED_CLIENT_TYPE_CUSTOMER_MOBILE_APP
        ),
        recipient=participant_pb2.Participant(
            din=din
        ),
        authorization=authorization_message
    )

    # Build the RoutableMessage containing the MessageEnvelope.
    routable_message = routable_message_pb2.RoutableMessage(
        to_destination=destination_pb2.Destination(
            domain=domain_pb2.DOMAIN_ENERGY_DEVICE
        ),
        protobuf_message_as_bytes=message_envelope.SerializeToString(),
        uuid=str(uuid.uuid4()).encode()
    )

    # Generate a signature expiration time.
    # Round up to nearest second and add 12 seconds.
    expires_at = math.ceil(time.time()) + 12

    # Build the TLV payload to sign.
    tlv_encoded_message = b''.join([
        to_tlv(tag_pb2.TAG_SIGNATURE_TYPE, signature_type_pb2.SIGNATURE_TYPE_RSA.to_bytes()),
        to_tlv(tag_pb2.TAG_DOMAIN, domain_pb2.DOMAIN_ENERGY_DEVICE.to_bytes()),
        to_tlv(tag_pb2.TAG_PERSONALIZATION, din.encode()),
        to_tlv(tag_pb2.TAG_EXPIRES_AT, expires_at.to_bytes(4)),
        tag_pb2.TAG_END.to_bytes(),
        routable_message.protobuf_message_as_bytes
    ])

    # Sign message and add the signature.
    routable_message.signature_data.CopyFrom(
        signature_data_pb2.SignatureData(
            signer_identity=key_identity_pb2.KeyIdentity(
                public_key=public_key_bytes
            ),
            rsa_data=rsa_signature_data_pb2.RsaSignatureData(
                expires_at=expires_at,
                signature=private_key.sign(
                    data=tlv_encoded_message,
                    padding=padding.PKCS1v15(),
                    algorithm=hashes.SHA512()
                )
            )
        )
    )

    # Return the signed routable Tesla Energy Gateway (TEG) message.
    return routable_message

def pair_device(args):
    # Load configuration.
    with open('configuration/credentials.json', mode='r', encoding='utf-8') as json_file:
        configuration = json.load(json_file)

    if 'paired_device' in configuration.get('gateway', {}):
        raise ValueError(
            'You already have device pairing information in the configuration.\n'
            'To prevent overwriting an existing pairing this program will not continue.\n'
            'Please delete the paired_device from the configuration to attempt to re-pair again.'
        )

    # Get an authenticated instance of the Tesla® Owner API.
    owner_api = get_tesla_api_session(configuration)

    # Get the Tesla® Energy Site ID.
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
    configuration['gateway']['paired_device'] = {
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
                            'description': args.device_name
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
    print('Please toggle a single Powerwall power switch for Gateway to accept pairing request.')

    # Repeat for 2 minutes (120 seconds), every 5 seconds = 24 iterations
    for _ in range(24):
        # Call internal function to list the paired devices.
        _list_devices(owner_api, energy_site_id)

        # Wait for 5 seconds before the next iteration.
        time.sleep(5)

def list_devices(args):
    # Load configuration.
    with open('configuration/credentials.json', mode='r', encoding='utf-8') as json_file:
        configuration = json.load(json_file)

    # Get an authenticated instance of the Tesla® Owner API.
    owner_api = get_tesla_api_session(configuration)

    # Get the energy site ID.
    energy_site_id = get_or_update_tesla_energy_site_id(configuration, owner_api)

    # Call internal function to list the paired devices.
    _list_devices(owner_api, energy_site_id)

def unpair_device(args):
    # Load configuration.
    with open('configuration/credentials.json', mode='r', encoding='utf-8') as json_file:
        configuration = json.load(json_file)

    # Get the Gateway Device Identification Number (DIN).
    gateway_din = configuration.get('gateway', {}).get('din')
    if not gateway_din:
        raise ValueError('Gateway Device Identification Number (DIN) not set in configuration.')

    # Get the private and public key of the paired 'phone'.
    paired_device = configuration.get('gateway', {}).get('paired_device')
    if not paired_device:
        raise ValueError('No paired_device in the configuration file. Please pair this device first.')
    private_key_bytes = base64.b64decode(paired_device.get('private_key'))
    private_key = serialization.load_der_private_key(private_key_bytes, password=None)
    public_key_bytes = base64.b64decode(paired_device.get('public_key'))

    # Get an authenticated instance of the Tesla® Owner API.
    owner_api = get_tesla_api_session(configuration)

    # Get the Tesla® Energy Site ID.
    energy_site_id = get_or_update_tesla_energy_site_id(configuration, owner_api)

    # Build a Authorization API Remove Authorized Client Request.
    remove_authorized_client_request = authorization_api_remove_authorized_client_request_pb2.AuthorizationAPIRemoveAuthorizedClientRequest(
        public_key=base64.b64decode(args.key)
    )

    # Build a AuthorizationMessages containing the AuthorizationAPIRemoveAuthorizedClientRequest.
    authorization_message = authorization_messages_pb2.AuthorizationMessages(
        remove_authorized_client_request=remove_authorized_client_request
    )

    # Get the signed routable message.
    routable_message = get_signed_routable_authorization_message(private_key, public_key_bytes, gateway_din, authorization_message)

    # Send the Remove Authorized Client Request via Owner API.
    response = owner_api.api_call(
        path=f'/api/1/energy_sites/{energy_site_id}/command',
        method='POST',
        json={
            'command_properties': {
                'message': {
                    'routable_message': base64.b64encode(routable_message.SerializeToString()).decode("ascii"),
                },
                'identifier_type': 1
            },
            'command_type': 'grpc_signed_command'
        }
    )

    # Print out the server's response.
    print(json.dumps(response, indent=4))

def main():
    """
    Main function for managing Tesla® Gateway paired devices.

    This function loads credentials from a JSON file, initializes a session with Tesla® Owner API
    generates cryptographic keys, shares the public one with Tesla® so that authenticated commands
    can be sent.

    Args:
        None

    Returns:
        None
    """

    # Set up command line argument parsing.
    parser = argparse.ArgumentParser(description='A program to manage paired devices with pair, list and unpair commands.')

    # Create subparsers to handle different commands.
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Create the parser for the "/pair" command.
    add_parser = subparsers.add_parser('pair', help='Pair a new device.')
    add_parser.add_argument('device_name', default='Tesla-API', help='Name of the device to add.')
    add_parser.set_defaults(func=pair_device)

    # Create the parser for the "/list" command.
    list_parser = subparsers.add_parser('list', help='List all paired devices.')
    list_parser.set_defaults(func=list_devices)

    # Create the parser for the "/unpair" command.
    remove_parser = subparsers.add_parser('unpair', help='Remove a paired device by its key.')
    remove_parser.add_argument('key', help='The public key of the device to unpair.')
    remove_parser.set_defaults(func=unpair_device)

    # Parse the arguments.
    args = parser.parse_args()

    # Call the appropriate function based on the subcommand used.
    if hasattr(args, 'func'):
        args.func(args)
    else:
        # If no subcommand is provided, display help message.
        parser.print_help()
        sys.exit(1)

# Launch the main method if invoked directly.
if __name__ == '__main__':
    main()
