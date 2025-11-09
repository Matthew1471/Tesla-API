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
- Start Max Backup on the Tesla® Powerwall® if during a session.
"""

# Used to convert the data to Base64.
import base64

# We manipulate dates and times.
import datetime

# This script makes heavy use of JSON parsing.
import json

# Used to convert a time to an expiration time.
import math

# Text in variables is dedented while still maintaing source code indentation.
import textwrap

# We compare against the epoch time.
import time

# We generate unique IDs (uuids).
import uuid

# All the shared Tesla® API functions are in this package.
from tesla_api.cloud.authentication import Authentication
from tesla_api.local.gateway import Gateway
from tesla_api.cloud.owner_api import OwnerAPI

# All the protobuf messages and types are in these packages.
from tesla_api.protobuf.energy_device.v1 import (
    authorized_client_pb2,
    control_event_scheduling_info_pb2,
    delivery_channel_pb2,
    message_envelope_pb2,
    participant_pb2,
    teg_api_cancel_manual_backup_event_request_pb2,
    teg_api_schedule_manual_backup_event_request_pb2,
    teg_messages_pb2
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

# All the shared Octopus Energy® functions are in this package.
from tesla_api.octopus_energy import OctopusEnergy

# We perform cryptographic operations.
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Third party library for dealing with protobuf data;
# "pip install protobuf" if getting import errors.
from google.protobuf import json_format
from google.protobuf.timestamp_pb2 import Timestamp

# The method to send the messages over (either OwnerAPI or LocalAPI).
SEND_VIA = 'LocalAPI'

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

def query_octopus_energy_graphql(octopus_energy, device_id):
    """
    Queries the Octopus Energy® API for the Flex planned dispatch data.

    Args:
        device_id (str): The Octopus Energy® Flex device ID to query.

    Returns:
        dict: JSON response containing the requested data.
    """

    # Build the FlexPlannedDispatches query (https://developer.octopus.energy/graphql/reference/queries/#apisite:flexplanneddispatches).
    query = textwrap.dedent(
        """
        query FlexPlannedDispatches($deviceId: String!) {
          flexPlannedDispatches(deviceId: $deviceId) {
            start
            end
            type
            energyAddedKwh
          }
        }
        """
    ).strip()

    variables = {'deviceId': device_id}

    # Request the flexPlannedDispatches.
    response = octopus_energy.api_call(query, variables)

    # Clean and return the response (there's an excessive amount of nesting otherwise).
    return response.get('data').get('flexPlannedDispatches')

def get_or_update_octopus_energy_device_id(configuration, octopus_energy):
    """
    Queries the Octopus Energy® API for the Flex device data.
    Then also updates the configuration file to include it.

    Args:
        configuration (dict): The full configuration dictionary.
        octopus_energy (OctopusEnergy): An instantiated OctopusEnergy object for querying data.

    Returns:
        dict: JSON response containing the requested data.
    """

    # Get a reference to the 'octopus_energy' section of the configuration.
    octopus_configuration = configuration.get('octopus_energy')

    # Save time (and reduce ambiguity) by setting an device_id in the configuration.
    if 'device_id' in octopus_configuration:
        return octopus_configuration.get('device_id')

    if 'account_number' not in octopus_configuration:
        raise ValueError('Missing account_number in Octopus configuration.')

    # Build the Devices query (https://developer.octopus.energy/graphql/reference/queries/#apisite:devices).
    query = textwrap.dedent(
        """
        query Devices($accountNumber: String!) {
          devices(accountNumber: $accountNumber) {
            id
            name
            deviceType
          }
        }
        """
    ).strip()

    variables = {'accountNumber': octopus_configuration.get('account_number')}

    # Request the flexPlannedDispatches.
    response = octopus_energy.api_call(query, variables)

    # Clean and return the response (there's an excessive amount of nesting otherwise).
    # Remove any "ELECTRICITY_METERS" in the list.
    device_ids = [item for item in response.get('data').get('devices') if item.get('deviceType') != 'ELECTRICITY_METERS']

    # Print the device_id for the user.
    print('Found Device ID(s): ', end='')
    print(*device_ids, sep=', ')

    # It is undesirable to monitor an arbitrary device.
    if len(device_ids) != 1:
        raise ValueError(
            f'You have {len(device_ids)} Flex devices under this account. '
            'You must manually set one to monitor in the configuration.'
        )

    # Pick the only device_id.
    device_id = device_ids[0].get('id')

    # Store the device_id for future use.
    # Add or update the device_id in the configuration.
    octopus_configuration['device_id'] = device_id

    # Update the file to include the modified device_id.
    with open('configuration/credentials.json', mode='w', encoding='utf-8') as json_file:
        json.dump(configuration, json_file, indent=4)

    # Return the discovered device_id.
    return device_id

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
    # Add or update the energy_site_id in the configuration.
    configuration['tesla']['energy_site_id'] = energy_site_id

    # Update the file to include the modified energy_site_id.
    with open('configuration/credentials.json', mode='w', encoding='utf-8') as json_file:
        json.dump(configuration, json_file, indent=4)

    # Return the discovered energy_site_id.
    return energy_site_id

def get_routable_message(domain, protobuf_message_as_bytes, public_key):
    # Build the routable message containing the message envelope.
    return routable_message_pb2.RoutableMessage(
        to_destination=destination_pb2.Destination(
            domain=domain
        ),
        signature_data=signature_data_pb2.SignatureData(
            signer_identity=key_identity_pb2.KeyIdentity(
                public_key=public_key
            )
        ),
        protobuf_message_as_bytes=protobuf_message_as_bytes,
        uuid=str(uuid.uuid4()).encode()
    )

def get_message_envelope(gateway_din, teg_message):
    # Build the message envelope containing the teg_message.
    return message_envelope_pb2.MessageEnvelope(
        delivery_channel=delivery_channel_pb2.DELIVERY_CHANNEL_HERMES_COMMAND,
        sender=participant_pb2.Participant(
            authorized_client=authorized_client_pb2.AUTHORIZED_CLIENT_TYPE_CUSTOMER_MOBILE_APP
        ),
        recipient=participant_pb2.Participant(
            # Device Identification Number (DIN) 
            din=gateway_din
        ),
        teg=teg_message
    )

def to_expires_at(epoch: float = 0) -> int:
    OFFSET = 12

    if epoch <= 0:
        epoch = time.time()  # Current time in seconds.

    # Round up to nearest second and add OFFSET seconds.
    return math.ceil(epoch) + OFFSET

def to_tlv(tag: int, value_bytes: bytes) -> list[bytes]:
    """
    Converts a tag and value buffer into a list of buffers representing the TLV structure
    [Tag, Length, Value] or [Tag, Value].
    """

    # Convert the tag to a single byte.
    tag_bytes = tag.to_bytes()

    # Check if the tag is TAG_END.
    if tag == tag_pb2.TAG_END:
        # Return the tag byte and the value byte.
        return [tag_bytes, value_bytes]

    # Get the length of the value in bytes.
    length_bytes = len(value_bytes).to_bytes()

    # Return a list of the three components.
    return [tag_bytes, length_bytes, value_bytes]

def build_tlv_payload(din: str, expires_at: int, protobuf_bytes: bytes) -> bytes:
    return b''.join([
        *to_tlv(tag_pb2.TAG_SIGNATURE_TYPE, signature_type_pb2.SIGNATURE_TYPE_RSA.to_bytes()),
        *to_tlv(tag_pb2.TAG_DOMAIN, domain_pb2.DOMAIN_ENERGY_DEVICE.to_bytes()),
        *to_tlv(tag_pb2.TAG_PERSONALIZATION, din.encode()),
        *to_tlv(tag_pb2.TAG_EXPIRES_AT, expires_at.to_bytes(4)),
        *to_tlv(tag_pb2.TAG_END, protobuf_bytes)
    ])

def sign_message(private_key, din, routable_message):
    # Generate a signature expiration time.
    expires_at = to_expires_at()

    # Build the TLV payload to sign.
    tlv_encoded_message = build_tlv_payload(din, expires_at, routable_message.protobuf_message_as_bytes)

    # Sign message and add the signature.
    routable_message.signature_data.CopyFrom(
        signature_data_pb2.SignatureData(
            signer_identity=key_identity_pb2.KeyIdentity(
                public_key=private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.PKCS1
                )
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

def parse_message(message):
    # Step 1: Parse the top-level RoutableMessage message.
    routable_message = routable_message_pb2.RoutableMessage()
    routable_message.ParseFromString(message)
    print(f'Routable Message:\n\n{json_format.MessageToJson(routable_message, preserving_proto_field_name=True)}\n')

    # Step 3: Extract and parse the nested MessageEnvelope message.
    message_envelope = message_envelope_pb2.MessageEnvelope()
    message_envelope.ParseFromString(routable_message.protobuf_message_as_bytes)
    print(f'Message Envelope:\n\n{json_format.MessageToJson(message_envelope, preserving_proto_field_name=True)}\n')

def update_tesla_max_backup_until_configuration(configuration, max_backup_until):
    """
    Update the Tesla® energy site max_backup_until configuration and save it to a JSON file.

    This function adds the provided max_backup_until under the 'tesla' key,
    updates the JSON file with the modified configuration.

    Args:
        configuration (dict): The main configuration dictionary to be updated.
        max_backup_until (int): The new max_backup_until value.

    Returns:
        None

    Raises:
        IOError: If there is an error while writing to the JSON file.
    """

    # Add or update the energy_site_id in the configuration.
    configuration['tesla']['max_backup_until'] = max_backup_until

    # Update the file to include the modified energy_site_id.
    with open('configuration/credentials.json', mode='w', encoding='utf-8') as json_file:
        json.dump(configuration, json_file, indent=4)

def send_routable_message(configuration, gateway_din, routable_message):
    if SEND_VIA == 'LocalAPI':
        # Send request locally over LAN.
        gateway = Gateway(configuration.get('gateway', {}).get('host'))
        response = gateway.api_call('/tedapi/v1r', 'POST', data=routable_message.SerializeToString())

        # Print out the server's response.
        parse_message(response)
    elif SEND_VIA == 'OwnerAPI':
        # Get an authenticated instance of the Tesla® Owner API.
        owner_api = get_tesla_api_session(configuration)

        # Get the energy site ID.
        energy_site_id = get_or_update_tesla_energy_site_id(configuration, owner_api)

        # Send the request via Owner API.
        response = owner_api.api_call(
            path=f'/api/1/energy_sites/{energy_site_id}/device_command',
            method='POST',
            json={
                'data': {
                    'routable_message': base64.b64encode(routable_message.SerializeToString()).decode("ascii"),
                    'identifier_type': 1,
                    'target_id': gateway_din
                    }
            }
        )

        # Print out the server's response.
        print(json.dumps(response, indent=4))
    else:
        raise ValueError('Unknown SEND_VIA method set.')

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

    # Get the Gateway Device Identification Number (DIN).
    gateway_din = configuration.get('tesla', {}).get('gateway_din', {})
    if not gateway_din:
        raise ValueError('Gateway Device Identification Number (DIN) not set in configuration.')

    # Get the private and public key of the paired 'phone'.
    paired_device = configuration.get('tesla', {}).get('paired_device', {})
    if not paired_device:
        raise ValueError('No paired_device in the configuration file. Please pair this device first.')
    private_key_bytes = base64.b64decode(paired_device.get('private_key'))
    private_key = serialization.load_der_private_key(private_key_bytes, password=None)
    public_key = base64.b64decode(paired_device.get('public_key'))

    # Get a reference to the 'octopus_energy' section of the configuration.
    octopus_energy_configuration = configuration.get('octopus_energy')

    # Get an authenticated instance of the Octopus Energy® API.
    octopus_energy = get_octopus_energy_api_session(configuration)

    # Get the Flex Device ID.
    device_id = get_or_update_octopus_energy_device_id(configuration, octopus_energy)

    # Get the octopus_planned_dispatches.
    octopus_planned_dispatches = query_octopus_energy_graphql(octopus_energy, device_id)

    # Output the current time.
    current_time = datetime.datetime.now().astimezone()
    print(f'Current Time: {current_time}')

    # Get current Max Backup status.
    max_backup_until = configuration.get('tesla', {}).get('max_backup_until', 0)
    if current_time.timestamp() < max_backup_until:
        print(f'Max Backup: Active Until {datetime.datetime.fromtimestamp(max_backup_until)}\n')
    else:
        print('Max Backup: Currently Inactive\n')

    # Evaluate planned dispatches.
    should_max_backup_until = None

    for planned_dispatch in octopus_planned_dispatches:
        start = datetime.datetime.fromisoformat(planned_dispatch['start']).astimezone()
        end = datetime.datetime.fromisoformat(planned_dispatch['end']).astimezone()
        print(f'{start} -> {end} ({planned_dispatch['energyAddedKwh']} kW via {planned_dispatch['type'].title()})')

        if start < current_time < end:
            should_max_backup_until = int(end.timestamp())

    # Output a new line.
    print()

    # Update Tesla®.
    if should_max_backup_until and max_backup_until < current_time.timestamp():
        # Notify the user.
        print('Action: Start Max Backup!\n')

        # Take a reference of the current time.
        current_time = int(time.time())

        # Build a Tesla Energy Gateway (TEG) API schedule manual backup event request.
        schedule_manual_backup_event_request = teg_api_schedule_manual_backup_event_request_pb2.TEGAPIScheduleManualBackupEventRequest(
            scheduling_info=control_event_scheduling_info_pb2.ControlEventSchedulingInfo(
                start_time=Timestamp(seconds=current_time),
                duration_seconds=should_max_backup_until-current_time,
                priority=(1 << 64) - 1 # MAX_UINT64
            )
        )

        # Build a Tesla Energy Gateway (TEG) message containing the schedule_manual_backup_event_request.
        teg_message = teg_messages_pb2.TEGMessages(
            schedule_manual_backup_event_request=schedule_manual_backup_event_request
        )

        # Get the message envelope.
        message_envelope = get_message_envelope(gateway_din, teg_message)

        # Serialize the message envelope to a string.
        protobuf_message_as_bytes = message_envelope.SerializeToString()

        # Get the routable message.
        routable_message = get_routable_message(domain_pb2.DOMAIN_ENERGY_DEVICE, protobuf_message_as_bytes, public_key)

        # Sign the routable message.
        sign_message(private_key, gateway_din, routable_message)

        # Print to console the routable message.
        parse_message(routable_message.SerializeToString())

        # Send the message.
        send_routable_message(configuration, gateway_din, routable_message)

        # Update configuration file.
        update_tesla_max_backup_until_configuration(configuration, should_max_backup_until)

    elif not should_max_backup_until and current_time.timestamp() < max_backup_until:
        # Notify the user.
        print('Action: Stop Max Backup!')

        # Build a Tesla Energy Gateway (TEG) API cancel manual backup event request.
        cancel_manual_backup_event_request = teg_api_cancel_manual_backup_event_request_pb2.TEGAPICancelManualBackupEventRequest()

        # Build a Tesla Energy Gateway (TEG) message containing the cancel_manual_backup_event_request.
        teg_message = teg_messages_pb2.TEGMessages(
            cancel_manual_backup_event_request=cancel_manual_backup_event_request
        )

        # Get the message envelope.
        message_envelope = get_message_envelope(gateway_din, teg_message)

        # Serialize the message envelope to a string.
        protobuf_message_as_bytes = message_envelope.SerializeToString()

        # Get the routable message.
        routable_message = get_routable_message(domain_pb2.DOMAIN_ENERGY_DEVICE, protobuf_message_as_bytes, public_key)

        # Sign the routable message.
        sign_message(private_key, gateway_din, routable_message)

        # Print to console the routable message.
        parse_message(routable_message.SerializeToString())

        # Send the message.
        send_routable_message(configuration, gateway_din, routable_message)

        # Update configuration file.
        update_tesla_max_backup_until_configuration(configuration, None)
    else:
        print('Nothing to do.')

# Launch the main method if invoked directly.
if __name__ == '__main__':
    main()
