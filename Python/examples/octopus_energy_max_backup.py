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
This example provides functionality to interact with the Octopus Energy® API for monitoring
Intelligent Octopus Go dynamic Flex planned dispatch times and then applying them to the Tesla®
Powerwall®.

The functions in this module allow you to:
- Establish an Octopus Energy® API session.
- Fetch dynamic Flex planned dispatch times.
- Start Max Backup on the Tesla® Powerwall® if during a session and stop if a session changes.
"""

# Used to convert the data to Base64.
import base64

# We manipulate dates and times.
import datetime

# This script makes heavy use of JSON parsing.
import json

# Used to convert a time to an expiration time.
import math

# We gracefully exit if during specific times.
import sys

# Text in variables is dedented while still maintaing source code indentation.
import textwrap

# We compare against the epoch time.
import time

# We generate unique IDs (uuids).
import uuid

# We perform cryptographic operations.
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Third party library for dealing with protobuf data;
# "pip install protobuf" if getting import errors.
from google.protobuf import json_format
from google.protobuf.timestamp_pb2 import Timestamp

# All the shared Tesla® API functions are in this package.
from tesla_api.cloud.authentication import Authentication
from tesla_api.local.gateway import Gateway
from tesla_api.cloud.owner_api import OwnerAPI

# All the protobuf messages and types are in these packages.
from tesla_api.protobuf.energy_device.v1 import (
    authorized_client_type_pb2,
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

    # Build the FlexPlannedDispatches query
    # (https://developer.octopus.energy/graphql/reference/queries/#apisite:flexplanneddispatches).
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

    # Build the Devices query
    # (https://developer.octopus.energy/graphql/reference/queries/#apisite:devices).
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

    # Can this be parsed.
    if 'data' not in response or 'devices' not in response['data']:
        raise ValueError('Unable to process Octopus Energy® devices response.')

    # Clean and return the response (there's an excessive amount of nesting otherwise).
    # Remove any "ELECTRICITY_METERS" in the list.
    device_ids = [
        device
        for device in response['data']['devices']
        if device.get('deviceType') != 'ELECTRICITY_METERS'
    ]

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

    # Add the token_configuration to the configuration.
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

        # Try refresh token if available and not expired.
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

    # It is undesirable to change Max Backup settings on an arbitrary site.
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

def get_signed_routable_teg_message(private_key, public_key_bytes, din, teg_message):
    # Build the message envelope containing the teg_message.
    message_envelope = message_envelope_pb2.MessageEnvelope(
        delivery_channel=delivery_channel_pb2.DELIVERY_CHANNEL_HERMES_COMMAND,
        sender=participant_pb2.Participant(
            authorized_client=authorized_client_type_pb2.AUTHORIZED_CLIENT_TYPE_CUSTOMER_MOBILE_APP
        ),
        recipient=participant_pb2.Participant(
            # Device Identification Number (DIN).
            din=din
        ),
        teg=teg_message
    )

    # Build the routable message containing the message envelope.
    routable_message = routable_message_pb2.RoutableMessage(
        to_destination=destination_pb2.Destination(
            domain=domain_pb2.DOMAIN_ENERGY_DEVICE
        ),
        # Serialize the message envelope to a string.
        protobuf_message_as_bytes=message_envelope.SerializeToString(),
        uuid=str(uuid.uuid4()).encode()
    )

    # Generate a signature expiration time.
    # Round up to nearest second and add 12 seconds.
    expires_at = math.ceil(time.time()) + 12

    # Build the TLV payload to sign.
    tlv_encoded_message = b"".join([
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

def to_tlv(tag: int, value_bytes: bytes) -> bytes:
    """
    Encodes a tag and value buffer into a TLV (Tag-Length-Value) byte structure:
    [Tag (1 byte), Length (1 byte), Value (N bytes)].
    """
    # Return the three components in TLV format.
    return tag.to_bytes() + len(value_bytes).to_bytes() + value_bytes

def parse_message(message):
    # Step 1: Parse the top-level RoutableMessage message.
    routable_message = routable_message_pb2.RoutableMessage()
    routable_message.ParseFromString(message)
    print(
        'Routable Message:\n\n'
        f'{json_format.MessageToJson(routable_message, preserving_proto_field_name=True)}\n'
    )

    # Step 2: Extract and parse the nested MessageEnvelope message.
    message_envelope = message_envelope_pb2.MessageEnvelope()
    message_envelope.ParseFromString(routable_message.protobuf_message_as_bytes)
    print(
        'Message Envelope:\n\n'
        f'{json_format.MessageToJson(message_envelope, preserving_proto_field_name=True)}\n'
    )

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

    # Add or update the max_backup_until in the configuration.
    configuration['tesla']['max_backup_until'] = max_backup_until

    # Update the file to include the modified max_backup_until.
    with open('configuration/credentials.json', mode='w', encoding='utf-8') as json_file:
        json.dump(configuration, json_file, indent=4)

def send_teg_message(configuration, private_key, public_key_bytes, gateway_din, teg_message):
    # Get the signed routable message.
    routable_message = get_signed_routable_teg_message(private_key, public_key_bytes, gateway_din, teg_message)

    # Print to console the routable message.
    print(
        'Request:\n'
        '--------\n'
    )
    parse_message(routable_message.SerializeToString())

    # Send the message.
    if SEND_VIA == 'LocalAPI':
        # Send request locally over LAN.
        gateway = Gateway(configuration.get('gateway', {}).get('host'))
        response = gateway.api_call('/tedapi/v1r', 'POST', data=routable_message.SerializeToString())

        # Print out the server's response.
        print(
            'Response:\n'
            '---------\n'
        )
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
        print(
            'Response:\n'
            '---------\n'
            f'{json.dumps(response, indent=4)}'
        )
    else:
        raise ValueError('Unknown SEND_VIA method set.')

def build_start_message(current_ts, planned_dispatch_until):
    # Build a Tesla Energy Gateway (TEG) API schedule manual backup event request.
    request = teg_api_schedule_manual_backup_event_request_pb2.TEGAPIScheduleManualBackupEventRequest(
        scheduling_info=control_event_scheduling_info_pb2.ControlEventSchedulingInfo(
            start_time=Timestamp(seconds=current_ts),
            duration_seconds=planned_dispatch_until-current_ts,
            priority=(1 << 64) - 1 # MAX_UINT64
        )
    )

    # Build a Tesla Energy Gateway (TEG) message containing the schedule_manual_backup_event_request.
    teg_message = teg_messages_pb2.TEGMessages(
        schedule_manual_backup_event_request=request
    )

    return teg_message

def build_stop_message():
    # Build a Tesla Energy Gateway (TEG) API cancel manual backup event request.
    request = teg_api_cancel_manual_backup_event_request_pb2.TEGAPICancelManualBackupEventRequest()

    # Build a Tesla Energy Gateway (TEG) message containing the cancel_manual_backup_event_request.
    teg_message = teg_messages_pb2.TEGMessages(
        cancel_manual_backup_event_request=request
    )

    return teg_message

def main():
    """
    Main function for starting Max Backup based off Octopus Energy® Intelligent dynamic times.

    This function loads credentials from a JSON file, checks we are within typically on-peak times
    initializes a session with Octopus Energy® API, retrieves the device planned dispatches
    (dynamic times), displays the information on the console and if within the planned dispatch
    time slot, activates max backup and deactivates any existing one if not.

    Args:
        None

    Returns:
        None
    """

    # Load configuration.
    with open('configuration/credentials.json', mode='r+', encoding='utf-8') as json_file:
        configuration = json.load(json_file)

    # Get a reference to the current datetime and the timestamp.
    current_dt = datetime.datetime.now().astimezone()
    current_ts = int(current_dt.timestamp())

    # Output the current time.
    print(f'Current Time: {current_dt}')

    # Abort if currently within the regular off-peak time.
    off_peak = configuration.get('octopus_energy', {}).get('off_peak', {})
    start = datetime.datetime.strptime(off_peak.get('Start', '23:30'), "%H:%M").time()
    end = datetime.datetime.strptime(off_peak.get('End', '05:30'), "%H:%M").time()

    # Check if current time is within the regular overnight off-peak window.
    current_time = current_dt.time()
    if current_time >= start or current_time < end:
        print('Action: Nothing to do (currently in regular off-peak window).\n')
        sys.exit(0)

    # Abort if currently within a 30 minute smart charging slot.
    backoff_ts = configuration.get('tesla', {}).get('max_backup_backoff')
    if backoff_ts is not None and current_ts < backoff_ts:
        print('Action: Nothing to do (currently in a smart charging slot).\n')
        sys.exit(0)

    # Get the Gateway Device Identification Number (DIN).
    gateway_din = configuration.get('tesla', {}).get('gateway_din')
    if not gateway_din:
        raise ValueError('Gateway Device Identification Number (DIN) not set in configuration.')

    # Get the private and public key of the paired 'phone'.
    paired_device = configuration.get('tesla', {}).get('paired_device', {})
    if not paired_device:
        raise ValueError('No paired_device in the configuration file. Please pair this device first.')
    private_key_bytes = base64.b64decode(paired_device.get('private_key'))
    private_key = serialization.load_der_private_key(private_key_bytes, password=None)
    public_key_bytes = base64.b64decode(paired_device.get('public_key'))

    # Get an authenticated instance of the Octopus Energy® API.
    octopus_energy = get_octopus_energy_api_session(configuration)

    # Get the Flex Device ID.
    device_id = get_or_update_octopus_energy_device_id(configuration, octopus_energy)

    # Get the octopus_planned_dispatches.
    octopus_planned_dispatches = query_octopus_energy_graphql(octopus_energy, device_id)

    # Get current Max Backup status.
    max_backup_until = configuration.get('tesla', {}).get('max_backup_until')
    if max_backup_until is not None and current_dt.timestamp() < max_backup_until:
        print(f'Max Backup: Active Until {datetime.datetime.fromtimestamp(max_backup_until)}')
    else:
        print('Max Backup: Currently Inactive')

    # Default: no planned dispatch.
    planned_dispatch_until = None

    # Evaluate the planned dispatches if there are any.
    if octopus_planned_dispatches:
        print('\nPlanned Dispatches:')

        # Evaluate planned dispatches.
        for planned_dispatch in octopus_planned_dispatches:
            start = datetime.datetime.fromisoformat(planned_dispatch['start']).astimezone()
            end = datetime.datetime.fromisoformat(planned_dispatch['end']).astimezone()
            print(
                f'{start} -> {end} '
                f'({planned_dispatch['energyAddedKwh']} kW via {planned_dispatch['type'].title()})'
            )

            # Is the current date and time within this planned dispatch period.
            if start < current_dt < end:
                planned_dispatch_until = int(end.timestamp())

        # Output a blank line.
        print()

    # Determine whether to start, reset or stop Max Backup.
    should_start_max_backup = (
        # We are in a planned dispatch time.
        planned_dispatch_until

        # And Max Backup is not currently active or has since expired.
        and (max_backup_until is None or max_backup_until < current_ts)
    )

    should_reset_max_backup = (
        # We are in a planned dispatch time.
        planned_dispatch_until

        # And Max Backup is currently active but the dispatch times have changed.
        and (max_backup_until is not None and max_backup_until != planned_dispatch_until)
    )

    should_stop_max_backup = (
        # We are not in a planned dispatch time.
        not planned_dispatch_until

        # But Max Backup is currently active.
        # And the current time is still within the configured Max Backup expiration time.
        and max_backup_until is not None and current_ts < max_backup_until
    )

    # Update Tesla® Gateway.
    if should_start_max_backup:
        # Notify the user.
        print('Action: Start Max Backup!\n')

        # Get the TEG Message.
        message = build_start_message(current_ts, planned_dispatch_until)

        # Get, sign and send a routable message.
        send_teg_message(configuration, private_key, public_key_bytes, gateway_din, message)

        # Update configuration file.
        update_tesla_max_backup_until_configuration(configuration, planned_dispatch_until)
    elif should_reset_max_backup:
        # Notify the user.
        print('Action: Reset Max Backup!\n')

        # Get the messages to send.
        messages = [
            build_stop_message(),
            build_start_message(current_ts, planned_dispatch_until)
        ]

        # Process each message.
        for message in messages:
            # Get, sign and send a routable message.
            send_teg_message(configuration, private_key, public_key_bytes, gateway_din, message)

        # Update configuration file.
        update_tesla_max_backup_until_configuration(configuration, planned_dispatch_until)
    elif should_stop_max_backup:
        # Notify the user.
        print('Action: Stop Max Backup!\n')

        # Get the TEG Message.
        message = build_stop_message()

        # Get, sign and send a routable message.
        send_teg_message(configuration, private_key, public_key_bytes, gateway_din, message)

        # Update configuration file.
        update_tesla_max_backup_until_configuration(configuration, None)
    else:
        print('Action: Nothing to do.\n')

    # We are within a 30 minute smart charging slot.
    if planned_dispatch_until:
        # Round up to the next 30-minute boundary
        HALF_HOUR_IN_SECONDS = 30 * 60
        time_to_next_boundary = HALF_HOUR_IN_SECONDS - (current_ts % HALF_HOUR_IN_SECONDS)
        configuration['tesla']['max_backup_backoff'] = current_ts + time_to_next_boundary

        # Update the file to include the modified max_backup_backoff.
        with open('configuration/credentials.json', mode='w', encoding='utf-8') as json_file:
            json.dump(configuration, json_file, indent=4)
    # Remove any existing reference to a smart charging slot.
    elif configuration.get("tesla", {}).get('max_backup_backoff'):
        # Remove max_backup_backoff from the config.
        configuration['tesla'].pop('max_backup_backoff', None)

        # Update the file to remove the max_backup_backoff.
        with open('configuration/credentials.json', mode='w', encoding='utf-8') as json_file:
            json.dump(configuration, json_file, indent=4)

# Launch the main method if invoked directly.
if __name__ == '__main__':
    main()
