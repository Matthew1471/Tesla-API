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
Tesla-API Authentication Module
This module provides classes and methods for interacting with the Tesla® authentication server.
It supports generating JWT tokens for use with the owner API.
"""

# Used to generate an OAuth 2.0 Proof Key for Code Exchange (PKCE) code verifier.
import base64
import hashlib
import random
import string

# We encode querystring params and extract the code from the returned OAuth 2.0 URL.
import urllib.parse

# We create a state variable to check the response for CSRF.
import secrets

# We need to invoke a web-browser to complete login.
import webbrowser

# We can check JWT claims/expiration first before making a request
# ("pip install pyjwt" if not already installed).
import jwt

# Third party library for making HTTP(S) requests;
# "pip install requests" if getting import errors.
import requests

# Remove urllib3 added user-agent (https://github.com/psf/requests/issues/5671)
import urllib3


class Authentication:
    """
    A class to talk to Tesla®'s Cloud based Authentication Server.
    """

    # Authentication host.
    AUTHENTICATION_HOST = 'https://auth.tesla.com'

    # This prevents the requests + urllib3 module from creating its own user-agent.
    HEADERS = {'User-Agent': urllib3.util.SKIP_HEADER, 'Accept': 'application/json'}

    # This sets a 10 second connect and read timeout.
    TIMEOUT = 10

    @staticmethod
    def authenticate():
        """
        Authenticate manually with Auth server (with a web browser) using OAuth 2.0.
        This is currently using the "Authorization Code Flow with Proof Key for Code Exchange
        (PKCE)" grant.

        Returns:
            tuple: A tuple containing the code verifier and state.
        """

        # OAuth 2.0 Proof Key for Code Exchange (PKCE) in case response is intercepted.
        uri_unreserved_characters = string.ascii_letters + string.digits + '-._~'
        code_verifier = ''.join(random.choices(uri_unreserved_characters, k=43))

        # This is sent in the initial request hashed
        # (before the auth server knows the plaintext to prove the request came from us).
        sha256_digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
        code_challenge = base64.urlsafe_b64encode(sha256_digest).decode('ascii').rstrip('=')

        # We create a state variable to check for Cross-Site Request Forgery (CSRF) attacks.
        state = secrets.token_urlsafe(32)

        # Build the login and authorisation code request (with PKCE) payload.
        params = {
            'audience': '',
            'client_id': 'ownerapi',
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'is_in_app': 'true',
            'locale': 'en-GB',
            'prompt': 'login',
            'redirect_uri': 'tesla://auth/callback',
            'response_type': 'code',
            'scope': 'openid email offline_access phone',
            'state': state
        }

        # Encode the parameters into a query string.
        query_string = urllib.parse.urlencode(params)

        # Construct the full URL.
        auth_url = f'{Authentication.AUTHENTICATION_HOST}/oauth2/v3/authorize?{query_string}'

        # Open the web browser to the authorization URL.
        webbrowser.open(auth_url, 2, False)

        # Return the generated code verifier and state variable.
        return code_verifier, state

    @staticmethod
    def parse_callback(expected_state, url):
        """
        Parse a user provided callback URL to obtain information useful for OAuth 2.0.
        This is currently using the "Authorization Code Flow with Proof Key for Code Exchange
        (PKCE)" grant.
        
        Args:
            expected_state (str): The expected Cross-Site Request Forgery (CSRF) variable.
            url (str): The URL containing the expected querystring values.

        Returns:
            str: A string containing the OAuth 2.0 authorisation code.
        """

        # Parse the URL.
        parsed = urllib.parse.urlparse(url)

        # Check the scheme is 'tesla' and the hostname is 'auth' and the path is '/callback'.
        if parsed.scheme != 'tesla' or parsed.hostname != 'auth' or parsed.path != '/callback':
            return None

        # Extract query parameters.
        query_params = urllib.parse.parse_qs(parsed.query)

        # Get the individual querystring values.
        code = query_params.get('code', [None])[0]
        state = urllib.parse.unquote(query_params.get('state', [None])[0])
        issuer = urllib.parse.unquote(query_params.get('issuer', [None])[0])

        # Validate the required fields.
        if not all([code, state, issuer]):
            return None

        # Check the issuer is 'https://auth.tesla.com/oauth2/v3'.
        if issuer != 'https://auth.tesla.com/oauth2/v3':
            return None

        # Check the state is what we expect.
        if state != expected_state:
            return None

        # Return the code.
        return code

    @staticmethod
    def get_token(code, code_verifier):
        """
        Perform an OAuth 2.0 authorisation code exchange for a token (with PKCE).
        This method does not require an open session on the authentication server.

        Args:
            code (str): The authorisation code.
            code_verifier (str): The PKCE code verifier.

        Returns:
            dict: The JSON response containing the token information.
        """

        # Build the exchange authorisation code for a token (with PKCE) request payload.
        data = {
            'redirect_uri': 'tesla://auth/callback',
            'client_id': 'ownerapi',
            'code': code,
            'code_verifier': code_verifier,
            'grant_type': 'authorization_code',
            'scope': 'openid email offline_access phone'
        }

        # This is used to exchange an authorisation code for a token.
        response = requests.post(
            url=f'{Authentication.AUTHENTICATION_HOST}/oauth2/v3/token',
            headers=Authentication.HEADERS,
            json=data,
            timeout=Authentication.TIMEOUT
        )

        # Return the JSON response.
        return response.json()

    @staticmethod
    def refresh_token(refresh_token):
        """
        Perform an OAuth 2.0 refresh token exchange for an access token.

        Args:
            refresh_token (str): The refresh_token.

        Returns:
            dict: The JSON response containing the token information.
        """

        # Build the exchange refresh token for an access token request payload.
        data = {
            'refresh_token': refresh_token,
            'scope': 'openid email offline_access phone',
            'client_id': 'ownerapi',
            'grant_type': 'refresh_token'
        }

        # This is used to exchange refresh token for an access token.
        response = requests.post(
            url=f'{Authentication.AUTHENTICATION_HOST}/oauth2/v3/token',
            headers=Authentication.HEADERS,
            json=data,
            timeout=Authentication.TIMEOUT
        )

        # Return the JSON response.
        return response.json()

    @staticmethod
    def check_token_valid(token, verify_signature=False):
        """
        This performs JWT token validation to confirm whether a token would likely be valid for an
        API call.

        Args:
            token (str):
                The JWT token.
            verify_signature (bool, optional):
                Whether to verify the token signature. Defaults to False.

        Returns:
            bool: True if the token is valid, False otherwise.
        """

        # We require "amr", "aud", "azp", "exp", "iat", "iss", "locale", "ou_code", "scp"
        # and "sub" values.
        require = ['amr', 'aud', 'azp', 'exp', 'iat', 'iss', 'locale', 'ou_code', 'scp', 'sub']

        try:
            # PyJWT requires "cryptography" to be able to support RS256.
            if verify_signature:
                # The Tesla® JWT public keys.
                # https://auth.tesla.com/oauth2/v3/.well-known/openid-configuration
                # -> https://auth.tesla.com/oauth2/v3/discovery/keys
                public_keys = {
                    'rP1gvN2bq1gdXGXXai38SB-tkv8': (
                        '-----BEGIN PUBLIC KEY-----\n'
                        'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvM8cWkjBEdbwOKHEVoVg\n'
                        'VCOPIZ9fNlGzKFIC9XuVJwDmHLg1pIqrzQi2sBdpTsk4B6Y2hRe+CcQ4bh58Od16\n'
                        'NQ1lrlrK7PZZRY4I/Zn0LEj0gC5E1tMDtgQElE5og+d/Rpn/wvkakFwv3ONDWJQ9\n'
                        'xCuD70fXVl3RlD2HNi86a/qU1sMI+Nd8Iux6fIRaJdX8+1V4yMTC2Db0PUts3f3Q\n'
                        'KPuOd0LFuQk00n054jNO3Ga6mFxwZEd6Mafq9KSybfB8vTtLe2VL0AC4sNVgB7lj\n'
                        'q/2kQW7B48eE3MsSJFsWhmhH/vzxTU7OdUfKdboEckop8kZb4qxVTfBcWndPsgsu\n'
                        'rQIDAQAB\n'
                        '-----END PUBLIC KEY-----\n'
                    ),
                    '29JHxvUAUQ_l9AUqappkWgKD8QE': (
                        '-----BEGIN PUBLIC KEY-----\n'
                        'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA06y0B5ZwxcZsEW1yfKxB\n'
                        'cdeeDihIN7c3XoB+T0e5oSE/yRR3NEXwXVARqY3hM75co+Ul1eqQTxtDs6V7wJ7X\n'
                        'zORFIeax4WG7gWqUxBNaFdaBL4cHCoT24a6CEbpa6Lxu/vZszdlwVJS2CevsMaOh\n'
                        'KNmAq7zDWSqJE4ixg5vC6Yf25HgcefsHmQroD8W4H//mb540xxz8XHnX9L4ZmL0Z\n'
                        'GKjWcZ26Z6UpNpCunvkcoDsOcBWHTPzNSkYenJKAPmjZhVb//5l7KlHOlDvF54oe\n'
                        'FYUZccEC9DyRoZsKnV2lA8qbnAhMGxaropfvEc/Phs4t1nQnMLJLWMbKOGgUHhJ6\n'
                        '2QIDAQAB\n'
                        '-----END PUBLIC KEY-----\n'
                    )
                }

                # Find which key is relevant for this token.
                kid = jwt.get_unverified_header(token)['kid']
                public_key = public_keys[kid]

                # Is the token still valid?
                jwt.decode(
                    jwt=token,
                    key=public_key,
                    algorithms='RS256',
                    options={'require':require},
                    audience=[
                        'https://owner-api.teslamotors.com/',
                        'https://auth.tesla.com/oauth2/v3/userinfo'
                    ],
                    issuer='https://auth.tesla.com/oauth2/v3'
                )
            else:
                # While the signature itself is not verified, we enforce required fields and
                # validate "aud", "iss", "exp" and "iat" values.
                options = {
                    'verify_signature':False,
                    'require':require,
                    'verify_aud':True,
                    'verify_iss':True,
                    'verify_exp':True,
                    'verify_iat':True
                }

                # Is the token still valid?
                jwt.decode(
                    jwt=token,
                    options=options,
                    audience=[
                        'https://owner-api.teslamotors.com/',
                        'https://auth.tesla.com/oauth2/v3/userinfo'
                    ],
                    issuer='https://auth.tesla.com/oauth2/v3'
                )

            # If we got to this line then no exceptions were generated by the above.
            return True

        # We mask the specific reason and just ultimately inform the user that the token is invalid.
        except (
            jwt.exceptions.InvalidTokenError,
            jwt.exceptions.DecodeError,
            jwt.exceptions.InvalidSignatureError,
            jwt.exceptions.ExpiredSignatureError,
            jwt.exceptions.InvalidAudienceError,
            jwt.exceptions.InvalidIssuerError,
            jwt.exceptions.InvalidIssuedAtError,
            jwt.exceptions.InvalidAlgorithmError,
            jwt.exceptions.MissingRequiredClaimError
        ):

            # The token is invalid.
            return False
