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

# We manipulate dates and times.
import datetime

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

# Third party library for dealing with protobuf data;
# "pip install protobuf" if getting import errors.
from google.protobuf import json_format

# All the protobuf messages and types are in these packages.
from tesla_api.protobuf.energy_device.v1 import (
    authorization_api_add_authorized_client_by_trusted_signature_request_pb2,
    authorization_api_add_authorized_client_request_pb2,
    authorization_api_configure_remote_service_request_pb2,
    authorization_api_get_signed_commands_public_key_request_pb2,
    authorization_api_list_authorized_clients_request_pb2,
    authorization_api_remove_authorized_client_request_pb2,
    authorization_messages_pb2,
    authorization_role_pb2,
    authorized_client_type_pb2,
    authorized_key_type_pb2,
    authorized_state_pb2,
    authorized_verification_type_pb2,
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
from tesla_api.local.gateway import Gateway

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

    # Return the signed routable Tesla® Energy Gateway (TEG) message.
    return routable_message

def pair_device_via_trusted(args):
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

    # Get an instance of the Gateway API.
    gateway = Gateway(configuration.get('gateway', {}).get('host'))

    # Generate a paired device key pair.
    new_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    new_private_key_bytes = new_private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    new_base64_private_key = base64.b64encode(new_private_key_bytes).decode('utf-8')
    print(f'Private Key:\n{new_base64_private_key}\n')

    new_public_key_bytes = new_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1
    )
    new_base64_public_key = base64.b64encode(new_public_key_bytes).decode('utf-8')
    print(f'Public Key:\n{new_base64_public_key}\n')

    # Get the signed routable message.
    routable_message = get_signed_routable_authorization_message(
        private_key=private_key,
        public_key_bytes=public_key_bytes,
        din=gateway_din,
        authorization_message=build_pair_with_trusted_signature_message(
            authorized_client_type=authorized_client_type_pb2.AUTHORIZED_CLIENT_TYPE_CUSTOMER_MOBILE_APP,
            description=args.device_name,
            key_type=authorized_key_type_pb2.AUTHORIZED_KEY_TYPE_RSA,
            public_key=new_public_key_bytes,
            roles=[authorization_role_pb2.AUTHORIZATION_ROLE_VEHICLE],
            identifier=None
        )
    )

    # Send the request locally over LAN.
    raw_response = gateway.api_call('/tedapi/v1r', 'POST', data=routable_message.SerializeToString())

    # Create new paired_device information in a fresh configuration.
    new_pairing = {
        'paired_device':{
            'private_key': new_base64_private_key,
            'public_key': new_base64_public_key
        }
    }

    # Create a filename on where to store the new configuration.
    filename = f'{args.device_name}.json'

    # Create a new file to include the new paired_device.
    with open(filename, mode='w', encoding='utf-8') as json_file:
        json.dump(new_pairing, json_file, indent=4)

    # Update the user.
    print(f'Credentials saved to "{args.device_name}.json".')

    # Parse the raw response as a RoutableMessage.
    response = routable_message_pb2.RoutableMessage.FromString(raw_response)

    # Obtain the MessageEnvelope from the RoutableMessage.
    message_envelope = message_envelope_pb2.MessageEnvelope.FromString(
        response.protobuf_message_as_bytes
    )

    # Print out the server's response.
    print(message_envelope)

def rename_device(args):
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

    # Get an instance of the Gateway API.
    gateway = Gateway(configuration.get('gateway', {}).get('host'))

    # Get the signed routable message.
    routable_message = get_signed_routable_authorization_message(
        private_key=private_key,
        public_key_bytes=public_key_bytes,
        din=gateway_din,
        authorization_message=build_pair_message(
            authorized_client_type=authorized_client_type_pb2.AUTHORIZED_CLIENT_TYPE_CUSTOMER_MOBILE_APP,
            description=args.device_name,
            key_type=authorized_key_type_pb2.AUTHORIZED_KEY_TYPE_RSA,
            public_key=public_key_bytes
        )
    )

    # Send the request locally over LAN.
    raw_response = gateway.api_call('/tedapi/v1r', 'POST', data=routable_message.SerializeToString())

    # Parse the raw response as a RoutableMessage.
    response = routable_message_pb2.RoutableMessage.FromString(raw_response)

    # Obtain the MessageEnvelope from the RoutableMessage.
    message_envelope = message_envelope_pb2.MessageEnvelope.FromString(
        response.protobuf_message_as_bytes
    )

    # Print out the server's response.
    print(message_envelope)

def list_devices(_):
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

    # Get an instance of the Gateway API.
    gateway = Gateway(configuration.get('gateway', {}).get('host'))

    # Get the signed routable message.
    routable_message = get_signed_routable_authorization_message(
        private_key=private_key,
        public_key_bytes=public_key_bytes,
        din=gateway_din,
        authorization_message=build_list_message()
    )

    # Send the request locally over LAN.
    raw_response = gateway.api_call('/tedapi/v1r', 'POST', data=routable_message.SerializeToString())

    # Parse the raw response as a RoutableMessage.
    response = routable_message_pb2.RoutableMessage.FromString(raw_response)

    # Obtain the MessageEnvelope from the RoutableMessage.
    message_envelope = message_envelope_pb2.MessageEnvelope.FromString(
        response.protobuf_message_as_bytes
    )

    # Check this is an authorization message containing list_authorized_clients_response.
    if not (
        message_envelope.HasField('authorization') 
        or message_envelope.authorization.HasField('list_authorized_clients_response')
    ):
        raise ValueError(f'An error occurred: {message_envelope}')

    # Get a reference to the list_authorized_clients_response.
    list_authorized_clients_response = message_envelope.authorization.list_authorized_clients_response

    print(f' * A Powerwall Power Switch Is Off: {list_authorized_clients_response.enable_line_switch_off}\n')

    # Iterate through the authorized clients.
    for client in list_authorized_clients_response.clients:
        lines = [
            f' {"-" * 80}',
            f' * Authorized Client Type        : {authorized_client_type_pb2.AuthorizedClientType.Name(client.type)}',
            f' * Authorized Client Description : {client.description}',
            f' * Authorized Key Type           : {authorized_key_type_pb2.AuthorizedKeyType.Name(client.key_type)}',
            f' * Authorized Public Key         : {base64.b64encode(client.public_key).decode("utf-8")}',
            f' * Authorization Roles           : {", ".join(authorization_role_pb2.AuthorizationRole.Name(role) for role in client.roles)}',
            f' * Authorized State              : {authorized_state_pb2.AuthorizedState.Name(client.state)}',
            f' * Authorized Verification Type  : {authorized_verification_type_pb2.AuthorizedVerificationType.Name(client.verification)}',
            f' * Added Time                    : {datetime.datetime.fromtimestamp(client.added_time.seconds).astimezone()}'
        ]

        # Only add identifier if explicitly set.
        if client.HasField('identifier'):
            lines.append(f' * Identifier                    : {client.identifier}')

        # Only add authorized_by_public_key if explicitly set.
        if client.HasField('authorized_by_public_key'):
            lines.append(f' * Authorized By Public Key      : {base64.b64encode(client.authorized_by_public_key).decode("utf-8")}')

        print('\n'.join(lines))

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

    # Get an instance of the Gateway API.
    gateway = Gateway(configuration.get('gateway', {}).get('host'))

    # Get the signed routable message.
    routable_message = get_signed_routable_authorization_message(
        private_key=private_key,
        public_key_bytes=public_key_bytes,
        din=gateway_din,
        authorization_message=build_unpair_message(public_key=base64.b64decode(args.key))
    )

    # Send the request locally over LAN.
    raw_response = gateway.api_call('/tedapi/v1r', 'POST', data=routable_message.SerializeToString())

    # Parse the raw response as a RoutableMessage.
    response = routable_message_pb2.RoutableMessage.FromString(raw_response)

    # Obtain the MessageEnvelope from the RoutableMessage.
    message_envelope = message_envelope_pb2.MessageEnvelope.FromString(
        response.protobuf_message_as_bytes
    )

    # Print out the server's response.
    print(message_envelope)

def get_signed_commands_public_key(_):
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

    # Get an instance of the Gateway API.
    gateway = Gateway(configuration.get('gateway', {}).get('host'))

    # Get the signed routable message.
    routable_message = get_signed_routable_authorization_message(
        private_key=private_key,
        public_key_bytes=public_key_bytes,
        din=gateway_din,
        authorization_message=build_get_signed_commands_public_key_message()
    )

    # Send the request locally over LAN.
    raw_response = gateway.api_call('/tedapi/v1r', 'POST', data=routable_message.SerializeToString())

    # Parse the raw response as a RoutableMessage.
    response = routable_message_pb2.RoutableMessage.FromString(raw_response)

    # Obtain the MessageEnvelope from the RoutableMessage.
    message_envelope = message_envelope_pb2.MessageEnvelope.FromString(
        response.protobuf_message_as_bytes
    )

    # Print out the server's response.
    print(message_envelope)

def enable_remote_service(_):
    # Load configuration.
    with open('configuration/credentials.json', mode='r', encoding='utf-8') as json_file:
        configuration = json.load(json_file)

    # Get the Gateway Device Identification Number (DIN).
    gateway_din = configuration.get('gateway', {}).get('din')
    if not gateway_din:
        raise ValueError('Gateway Device Identification Number (DIN) not set in configuration.')

    # Get the Tesla® Energy Site ID.
    site_id = configuration.get('tesla', {}).get('site_id')
    if not site_id:
        raise ValueError('Site ID not set in configuration.')

    # Get the private and public key of the paired 'phone'.
    paired_device = configuration.get('gateway', {}).get('paired_device')
    if not paired_device:
        raise ValueError('No paired_device in the configuration file. Please pair this device first.')
    private_key_bytes = base64.b64decode(paired_device.get('private_key'))
    private_key = serialization.load_der_private_key(private_key_bytes, password=None)
    public_key_bytes = base64.b64decode(paired_device.get('public_key'))

    # Get an instance of the Gateway API.
    gateway = Gateway(configuration.get('gateway', {}).get('host'))

    # Get the signed routable message.
    routable_message = get_signed_routable_authorization_message(
        private_key=private_key,
        public_key_bytes=public_key_bytes,
        din=gateway_din,
        authorization_message=build_configure_remote_service_message(2592000, site_id)
    )

    # Send the request locally over LAN.
    raw_response = gateway.api_call('/tedapi/v1r', 'POST', data=routable_message.SerializeToString())

    # Parse the raw response as a RoutableMessage.
    response = routable_message_pb2.RoutableMessage.FromString(raw_response)

    # Obtain the MessageEnvelope from the RoutableMessage.
    message_envelope = message_envelope_pb2.MessageEnvelope.FromString(
        response.protobuf_message_as_bytes
    )

    # Print out the server's response.
    print(message_envelope)

def build_pair_message(authorized_client_type, description, key_type, public_key):
    # Build a Authorization API Add Authorized Client Request.
    add_authorized_client_request = authorization_api_add_authorized_client_request_pb2.AuthorizationAPIAddAuthorizedClientRequest(
        type=authorized_client_type,
        description=description,
        key_type=key_type,
        public_key=public_key
    )

    # Build a AuthorizationMessages containing the AuthorizationAPIAddAuthorizedClientRequest.
    authorization_message = authorization_messages_pb2.AuthorizationMessages(
        add_authorized_client_request=add_authorized_client_request
    )

    return authorization_message

def build_pair_with_trusted_signature_message(authorized_client_type, description, key_type, public_key, roles, identifier):
    # Build a Authorization API Add Authorized Client By Trusted Signature Request.
    add_authorized_client_by_trusted_signature_request = authorization_api_add_authorized_client_by_trusted_signature_request_pb2.AuthorizationAPIAddAuthorizedClientByTrustedSignatureRequest(
        type=authorized_client_type,
        description=description,
        key_type=key_type,
        public_key=public_key,
        roles=roles,
        identifier=identifier
    )

    # Build a AuthorizationMessages containing the AuthorizationAPIAddAuthorizedClientByTrustedSignatureRequest.
    authorization_message = authorization_messages_pb2.AuthorizationMessages(
        add_authorized_client_by_trusted_signature_request=add_authorized_client_by_trusted_signature_request
    )

    return authorization_message

def build_list_message():
    # Build a Authorization API List Authorized Clients Request.
    list_authorized_clients_request = authorization_api_list_authorized_clients_request_pb2.AuthorizationAPIListAuthorizedClientsRequest()

    # Build a AuthorizationMessages containing the AuthorizationAPIListAuthorizedClientsRequest.
    authorization_message = authorization_messages_pb2.AuthorizationMessages(
        list_authorized_clients_request=list_authorized_clients_request
    )

    return authorization_message

def build_unpair_message(public_key):
    # Build a Authorization API Remove Authorized Client Request.
    remove_authorized_client_request = authorization_api_remove_authorized_client_request_pb2.AuthorizationAPIRemoveAuthorizedClientRequest(
        public_key=public_key
    )

    # Build a AuthorizationMessages containing the AuthorizationAPIRemoveAuthorizedClientRequest.
    authorization_message = authorization_messages_pb2.AuthorizationMessages(
        remove_authorized_client_request=remove_authorized_client_request
    )

    return authorization_message

def build_get_signed_commands_public_key_message():
    # Build a Authorization API Get Signed Commands Public Key Request.
    get_signed_commands_public_key_request = authorization_api_get_signed_commands_public_key_request_pb2.AuthorizationAPIGetSignedCommandsPublicKeyRequest()

    # Build a AuthorizationMessages containing the AuthorizationAPIGetSignedCommandsPublicKeyRequest.
    authorization_message = authorization_messages_pb2.AuthorizationMessages(
        get_signed_commands_public_key_request=get_signed_commands_public_key_request
    )

    return authorization_message

def build_configure_remote_service_message(duration_seconds, session_id, requester_email):
    # Build a Authorization API Configure Remote Service Request.
    configure_remote_service_request = authorization_api_configure_remote_service_request_pb2.AuthorizationAPIConfigureRemoteServiceRequest(
        duration_seconds=duration_seconds,
        session_id=session_id,
        requester_email=requester_email
    )

    # Build a AuthorizationMessages containing the AuthorizationAPIConfigureRemoteServiceRequest.
    authorization_message = authorization_messages_pb2.AuthorizationMessages(
        configure_remote_service_request=configure_remote_service_request
    )

    return authorization_message

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

    # Create the parser for the "/trusted_pair" command.
    add_parser = subparsers.add_parser('pair_via_trusted', help='Pair a new device (using an existing paired device).')
    add_parser.add_argument('device_name', nargs='?', default='Tesla-API', help='Name of the device to add.')
    add_parser.set_defaults(func=pair_device_via_trusted)

    # Create the parser for the "/rename" command.
    add_parser = subparsers.add_parser('rename', help='Rename this device.')
    add_parser.add_argument('device_name', nargs='?', default='Tesla-API', help='New name for this device.')
    add_parser.set_defaults(func=rename_device)

    # Create the parser for the "/list" command.
    list_parser = subparsers.add_parser('list', help='List all paired devices.')
    list_parser.set_defaults(func=list_devices)

    # Create the parser for the "/unpair" command.
    remove_parser = subparsers.add_parser('unpair', help='Remove a paired device by its key.')
    remove_parser.add_argument('key', help='The public key of the device to unpair.')
    remove_parser.set_defaults(func=unpair_device)

    # Create the parser for the "/signed_key" command.
    signed_parser = subparsers.add_parser('signed_key', help='Get the signed commands ECC public key.')
    signed_parser.set_defaults(func=get_signed_commands_public_key)

    # Create the parser for the "/service" command.
    service_parser = subparsers.add_parser('service', help='Enable Remote Service Access for your installer.')
    service_parser.set_defaults(func=enable_remote_service)

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
