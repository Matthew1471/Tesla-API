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

# Used to display the response in Base64.
import base64

# This script makes heavy use of JSON parsing.
import json

# Used to convert a time to an expiration time.
import math
import time

# We generate unique IDs (uuids).
import uuid

# We perform cryptographic operations.
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Third party library for dealing with protobuf data;
# "pip install protobuf" if getting import errors.
from google.protobuf import json_format
from google.protobuf.timestamp_pb2 import Timestamp

# All the protobuf messages and types are in these packages.
from tesla_api.protobuf.energy_device.v1 import (
    authorized_client_type_pb2,
    control_event_scheduling_info_pb2,
    common_api_get_networking_status_request_pb2,
    common_messages_pb2,
    delivery_channel_pb2,
    message_envelope_pb2,
    participant_pb2,
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

# For sending local commands.
from tesla_api.local.gateway import Gateway

# Whether to use real identifiable data from the configuration file
# (be careful if posting this online).
USE_FAKE_DATA = True

# Whether to demonstrate sending data.
SEND_DEMO = False


def to_tlv(tag: int, value_bytes: bytes) -> bytes:
    """
    Encodes a tag and value buffer into a TLV (Tag-Length-Value) byte structure:
    [Tag (1 byte), Length (1 byte), Value (N bytes)].
    """
    # Return the three components in TLV format.
    return tag.to_bytes() + len(value_bytes).to_bytes() + value_bytes

def build_tlv_payload(din: str, expires_at: int, routable_message) -> bytes:
    return b"".join([
        to_tlv(tag_pb2.TAG_SIGNATURE_TYPE, signature_type_pb2.SIGNATURE_TYPE_RSA.to_bytes()),
        to_tlv(tag_pb2.TAG_DOMAIN, domain_pb2.DOMAIN_ENERGY_DEVICE.to_bytes()),
        to_tlv(tag_pb2.TAG_PERSONALIZATION, din.encode()),
        to_tlv(tag_pb2.TAG_EXPIRES_AT, expires_at.to_bytes(4)),
        tag_pb2.TAG_END.to_bytes(),
        routable_message.protobuf_message_as_bytes
    ])

def sign_message(private_key, public_key_bytes, din, routable_message):
    # Generate a signature expiration time.
    # Round up to nearest second and add 12 seconds.
    expires_at = math.ceil(time.time()) + 12

    # Sign message and add the signature.
    routable_message.signature_data.CopyFrom(
        signature_data_pb2.SignatureData(
            signer_identity=key_identity_pb2.KeyIdentity(
                public_key=public_key_bytes
            ),
            rsa_data=rsa_signature_data_pb2.RsaSignatureData(
                expires_at=expires_at,
                signature=private_key.sign(
                    data=build_tlv_payload(din, expires_at, routable_message),
                    padding=padding.PKCS1v15(),
                    algorithm=hashes.SHA512()
                )
            )
        )
    )

def verify_signature(din, routable_message):
    # Load the public key from the signed message.
    public_key = serialization.load_der_public_key(routable_message.signature_data.signer_identity.public_key)

    # Obtain the signature expiration time.
    expires_at = routable_message.signature_data.rsa_data.expires_at

    # Verify the signature.
    public_key.verify(
        signature=routable_message.signature_data.rsa_data.signature,
        data=build_tlv_payload(din, expires_at, routable_message),
        padding=padding.PKCS1v15(),
        algorithm=hashes.SHA512()
    )

def generate_sample_message(private_key, public_key_bytes, gateway_din):
    # Build a Tesla Energy Gateway (TEG) API schedule manual backup event request.
    schedule_manual_backup_event_request = teg_api_schedule_manual_backup_event_request_pb2.TEGAPIScheduleManualBackupEventRequest(
        scheduling_info=control_event_scheduling_info_pb2.ControlEventSchedulingInfo(
            start_time=Timestamp(seconds=int(time.time())),
            duration_seconds=6000,
            priority=(1 << 64) - 1 # MAX_UINT64
        )
    )

    # Build a Tesla Energy Gateway (TEG) message containing the schedule_manual_backup_event_request.
    teg_message = teg_messages_pb2.TEGMessages(
        schedule_manual_backup_event_request=schedule_manual_backup_event_request
    )

    # Build the message envelope containing the teg_message.
    message_envelope = message_envelope_pb2.MessageEnvelope(
        delivery_channel=delivery_channel_pb2.DELIVERY_CHANNEL_HERMES_COMMAND,
        sender=participant_pb2.Participant(
            authorized_client=authorized_client_type_pb2.AUTHORIZED_CLIENT_TYPE_CUSTOMER_MOBILE_APP
        ),
        recipient=participant_pb2.Participant(
            din=gateway_din
        ),
        teg=teg_message
    )

    # Build the routable message containing the message envelope.
    routable_message = routable_message_pb2.RoutableMessage(
        to_destination=destination_pb2.Destination(
            domain=domain_pb2.DOMAIN_ENERGY_DEVICE
        ),
        protobuf_message_as_bytes=message_envelope.SerializeToString(),
        uuid=str(uuid.uuid4()).encode()
    )

    # Sign the message.
    sign_message(private_key, public_key_bytes, gateway_din, routable_message)

    # Return the routable message.
    return routable_message

def generate_sample_message2(private_key, public_key_bytes, gateway_din):
    # Build a Common API Get Networking Status Request.
    get_networking_status_request = common_api_get_networking_status_request_pb2.CommonAPIGetNetworkingStatusRequest()

    # Build a CommonMessage containing the CommonAPIGetNetworkingStatusRequest.
    common_message = common_messages_pb2.CommonMessages(
        get_networking_status_request=get_networking_status_request
    )

    # Build the MessageEnvelope containing the CommonMessage.
    message_envelope = message_envelope_pb2.MessageEnvelope(
        delivery_channel=delivery_channel_pb2.DELIVERY_CHANNEL_HERMES_COMMAND,
        sender=participant_pb2.Participant(
            authorized_client=authorized_client_type_pb2.AUTHORIZED_CLIENT_TYPE_CUSTOMER_MOBILE_APP
        ),
        recipient=participant_pb2.Participant(
            din=gateway_din
        ),
        common=common_message
    )

    # Build the RoutableMessage containing the MessageEnvelope.
    routable_message = routable_message_pb2.RoutableMessage(
        to_destination=destination_pb2.Destination(
            domain=domain_pb2.DOMAIN_ENERGY_DEVICE
        ),
        protobuf_message_as_bytes=message_envelope.SerializeToString(),
        uuid=str(uuid.uuid4()).encode()
    )

    # Sign the message.
    sign_message(private_key, public_key_bytes, gateway_din, routable_message)

    # Return the routable message.
    return routable_message

def parse_message(message, gateway_din=None, verify=True):
    # Step 1: Parse the top-level RoutableMessage message.
    routable_message = routable_message_pb2.RoutableMessage()
    routable_message.ParseFromString(message)
    print(f'Routable Message:\n\n{json_format.MessageToJson(routable_message, preserving_proto_field_name=True)}\n')

    # Step 2: Verify the signature.
    if verify:
        verify_signature(gateway_din, routable_message)

    # Step 3: Extract and parse the nested MessageEnvelope message.
    message_envelope = message_envelope_pb2.MessageEnvelope()
    message_envelope.ParseFromString(routable_message.protobuf_message_as_bytes)
    print(f'Message Envelope:\n\n{json_format.MessageToJson(message_envelope, preserving_proto_field_name=True)}\n')

# Launch the test method if invoked directly.
if __name__ == '__main__':

    # Load configuration.
    with open('configuration/credentials.json', mode='r+', encoding='utf-8') as json_file:
        configuration = json.load(json_file)

    if USE_FAKE_DATA:
        # Device Identification Number (DIN).
        gateway_din = '1152100-13-J--AA123456B7C89D'

        # Generate a fake paired device key pair.
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )

        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        print(f'Demo Private Key:\n{base64.b64encode(private_key_bytes)}\n')

        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.PKCS1
        )
        print(f'Demo Public Key:\n{base64.b64encode(public_key_bytes)}\n')
    else:
        # Get a reference to the tesla part of the configuration.
        tesla_configuration = configuration.get('tesla', {})

        # Get the Gateway's Device Identification Number (DIN).
        gateway_din = tesla_configuration.get('gateway_din')

        # Get the private and public key of the paired 'phone'.
        paired_device = tesla_configuration.get('paired_device', {})
        private_key_bytes = base64.b64decode(paired_device.get('private_key'))
        private_key = serialization.load_der_private_key(private_key_bytes, password=None)
        public_key_bytes = base64.b64decode(paired_device.get('public_key'))

    # Create a sample message.
    protobuf_bytes = generate_sample_message(private_key, public_key_bytes, gateway_din).SerializeToString()

    # Re-parse the sample message.
    parse_message(protobuf_bytes, gateway_din)

    # Demonstrate sending a request
    # (but only if using real data, fake data will not work).
    if not USE_FAKE_DATA and SEND_DEMO:
        # Create another sample message.
        protobuf_bytes = generate_sample_message2(private_key, public_key_bytes, gateway_din).SerializeToString()

        # Send this example to the Gateway via the LAN.
        gateway = Gateway(configuration.get('gateway', {}).get('host', None))
        response = gateway.api_call('/tedapi/v1r', 'POST', data=protobuf_bytes)

        # Decode response.
        parse_message(response, verify=False)
