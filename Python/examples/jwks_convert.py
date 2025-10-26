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
This example converts Tesla® authentication server public keys from JWKS to a PEM dictionary.
It supports generating PyJWT compatible keys for verification of the API tokens.
"""

# We attempt to make the output more readable.
import pprint

# Third party library for parsing JWK.
# ("pip install pyjwt" if not already installed).
import jwt

# Third party library for making HTTP(S) requests;
# "pip install requests" if getting import errors.
import requests

# Remove urllib3 added user-agent (https://github.com/psf/requests/issues/5671)
import urllib3

# We serialize keys to PEM format.
from cryptography.hazmat.primitives import serialization


# This prevents the requests + urllib3 module from creating its own user-agent.
HEADERS = {'User-Agent': urllib3.util.SKIP_HEADER, 'Accept': 'application/json'}

# This sets a 1 minute connect and read timeout.
TIMEOUT = 60

def jwks_to_pem(url):
    """
    This collects and converts JWKS auth public keys from an OAuth 2.0 server.

    This function requests and loads the JSON Web Key Set (JWKS) and converts it 
    to a dictionary of PEM.

    Args:
        url (str): The JWKS url.

    Returns:
        dict: keys indexed by JWK Key ID (kid).
    """

    # This is used to obtain the JSON Web Key Set (JWKS).
    response = requests.get(
        url=url,
        headers=HEADERS,
        timeout=TIMEOUT
    )

    # Obtain the JSON response.
    jwks = response.json()

    # Iterate through each JSON Web Key (JWK) in the JSON Web Key Set (JWKS).
    public_keys = {}
    for jwk in jwks['keys']:
        # Obtain the raw key.
        key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)

        # Convert the raw key to PEM format.
        public_pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Obtain the Key ID.
        kid = jwk['kid']

        # Set the public key dictionary to contain the public key PEM for this Key ID.
        public_keys[kid] = public_pem.decode()

    # Return the dictionary of public keys.
    return public_keys

def main():
    """
    Main function for collecting and displaying Tesla® auth public keys.

    This function loads the JSON Web Key Set (JWKS), converts it to a dictionary
    of PEM and displays the information on the console.

    Args:
        None

    Returns:
        None
    """

    # Obtain the public keys for the Owner API.
    public_keys = jwks_to_pem('https://auth.tesla.com/oauth2/v3/discovery/keys')

    # Output the dictionary to the console.
    pprint.pp(public_keys)

# Launch the main method if invoked directly.
if __name__ == '__main__':
    main()
