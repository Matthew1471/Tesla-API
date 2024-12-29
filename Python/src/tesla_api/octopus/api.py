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
Tesla-API Octopus Energy® API Module
This module provides functionality to interact with the Octopus Energy® API.
"""

# Allow the dictionary to be correctly encoded for the optional HTTP GET.
import json

# Text in variables is dedented while still maintaing source code indentation.
import textwrap

# Disable the automatic user-agent header.
import urllib3

# Third party library; "pip install requests" if getting import errors.
import requests


class Octopus:
    """
    A class to talk to Octopus Energy®'s GraphQL™ API.
    This supports maintaining an authenticated session between API calls.
    """

    # The Octopus Energy® GraphQL™ API URL.
    URL = 'https://api.octopus.energy/v1/graphql/'

    # This prevents the requests + urllib3 module from creating its own user-agent.
    HEADERS = {
        'User-Agent': urllib3.util.SKIP_HEADER,
        'Accept': 'application/graphql-response+json;charset=utf-8, application/json;charset=utf-8'
    }

    # This sets a 10 second connect and read timeout.
    TIMEOUT = 10

    # This could be returned by other mutations.
    POSSIBLE_ERROR_TYPE_FRAGMENT = textwrap.dedent("""
       fragment PossibleErrorTypeFragment on PossibleErrorType {
          code
          description
          message
          type
       }
    """).lstrip()

    def __init__(self):
        """
        Initialize an Octopus Energy® GraphQL™ API instance.
        """

        # Using a session means Requests supports keep-alive.
        self.session = requests.Session()

        # Create a copy of the original header dictionary.
        self.headers = Octopus.HEADERS.copy()

    def get_token_from_api_key(self, api_key):
        """
        Retrieve a Kraken token using the provided API key.

        This method sends the API key to the Octopus Energy® GraphQL™ API instance
        to obtain a Kraken authentication token.

        You can find your Octopus Energy® API key at:
            https://octopus.energy/dashboard/developer/

        Args:
            api_key (str): The Octopus Energy® API key used for authentication.

        Returns:
            dict: GraphQL™ JSON response containing the Kraken authentication JWT
                  and additional data.
        """
        return self._get_token({'APIKey': api_key})

    def get_token_from_email_and_password(self, email, password):
        """
        Retrieve a Kraken token using the provided API key.

        This method sends a username and password to the Octopus Energy® GraphQL™ API instance
        to obtain a Kraken authentication token.

        Args:
            email (str): The Octopus Energy® account e-mail address used for authentication.
            password (str): The Octopus Energy® account password used for authentication.

        Returns:
            dict: GraphQL™ JSON response containing the Kraken authentication JWT
                  and additional data.
        """
        return self._get_token({'email': email, 'password': password})

    def get_token_from_organisation_secret_key(self, organisation_secret_key):
        """
        Retrieve a Kraken token using the provided organisation secret API key.

        This method sends the API key to the Octopus Energy® GraphQL™ API instance
        to obtain a Kraken authentication token.

        Args:
            organisation_secret_key (str): The Octopus Energy® API key used for authentication.

        Returns:
            dict: GraphQL™ JSON response containing the Kraken authentication JWT
                  and additional data.
        """
        return self._get_token({'organizationSecretKey': organisation_secret_key})

    def get_token_from_pre_signed_key(self, pre_signed_key):
        """
        Retrieve a Kraken token using a pre-signed API key.

        This method sends the API key to the Octopus Energy® GraphQL™ API instance
        to obtain a Kraken authentication token.

        Args:
            pre_signed_key (str): The Octopus Energy® API key used for authentication.

        Returns:
            dict: GraphQL™ JSON response containing the Kraken authentication JWT
                  and additional data.
        """
        return self._get_token({'preSignedKey': pre_signed_key})

    def _get_token(self, obtain_json_web_token_input):
        """
        Retrieve a Kraken token for use with Octopus Energy® GraphQL™ API.

        Args:
            obtain_json_web_token_input (str): API secret for authentication.

        Returns:
            dict: GraphQL™ JSON response containing Kraken JWT if successful, error otherwise.
        """

        # Create a fresh copy of the original header dictionary.
        self.headers = Octopus.HEADERS.copy()

        # Build an GraphQL™ document using the obtainKrakenToken mutation.
        query = self.POSSIBLE_ERROR_TYPE_FRAGMENT + textwrap.dedent("""
        mutation ObtainKrakenToken($input: ObtainJSONWebTokenInput!) {
          obtainKrakenToken(input: $input) {
            possibleErrors {
              ...PossibleErrorTypeFragment
            }
            token
            payload
            refreshToken
            refreshExpiresIn
          }
        }
        """).rstrip()
        variables = {'input': obtain_json_web_token_input}

        # Return the GraphQL™ JSON response.
        return self.api_call(query, variables)

    def set_token(self, token):
        """
        Authenticates with the GraphQL™ API (with a JWT).

        Args:
            token (str): JWT for authentication.
        """

        # We append an OAuth 2.0 token to future requests.
        self.headers['Authorization'] = token

    def refresh_token(self, refresh_token):
        """
        Extend a Kraken token using a refresh token.

        This method sends the JWT to the Octopus Energy® GraphQL™ API instance
        to obtain an extended Kraken authentication token.

        Args:
            refresh_token (str): The Octopus Energy® API refresh token used for authentication.

        Returns:
            dict: GraphQL™ JSON response containing the Kraken authentication JWT
                  and additional data.
        """
        return self._get_token({'refreshToken': refresh_token})

    def api_call(self, query, variables=None, method='POST', debug=True):
        """
        Make an API call to the Octopus Energy® GraphQL™ API.

        Args:
            query (str):
                GraphQL™ document for the request.
            variables (dict, optional):
                Variables to substitute into the GraphQL™ document. Defaults to None.
            method (string, optional):
                The HTTP method to perform the GraphQL™ request via. Defaults to POST.
            debug (bool, optional):
                Whether to output any GraphQL™ extension metadata. Defaults to True.

        Returns:
            dict:
                GraphQL™ JSON response.
        """

        # Call the Octopus Energy® GraphQL™ API endpoint (with JSON data).
        response = self.session.request(
            method=method,
            url=self.URL,
            params={'query':query, 'variables': json.dumps(variables)} if method == 'GET' else None,
            headers=self.headers,
            json={'query':query, 'variables': variables} if method == 'POST' else None,
            timeout=Octopus.TIMEOUT
        )

        # Check the response is positive.
        if response.status_code != 200:
            # Any content should be more descriptive than the HTTP response codes.
            if len(response.content) > 0:
                raise ValueError(response.content)

            # Raise a generic HTTP error.
            raise ValueError(response.status_code + ' ' + response.reason)

        # Check there was content and convert to JSON if so.
        response_json = response.json() if len(response.content) > 0 else None

        # Was a GraphQL™ error present?
        if 'errors' in response_json:
            raise ValueError(json.dumps(response_json['errors'], indent=4))

        # Was a GraphQL™ extension present?
        if debug and 'extentions' in response_json:
            print(json.dumps(response_json['extentions'], indent=4))

        # Return the GraphQL™ JSON response.
        return response_json
