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
Tesla-API Owner API Module
This module provides classes and methods for interacting with the Tesla® owner API server.
It supports maintaining an authenticated session and making requests.
"""

# We can check JWT claims/expiration first before making a request
# ("pip install pyjwt" if not already installed).
import jwt

# Third party library for making HTTP(S) requests;
# "pip install requests" if getting import errors.
import requests

# Remove urllib3 added user-agent (https://github.com/psf/requests/issues/5671)
import urllib3


class OwnerAPI:
    """
    A class to talk to Tesla®'s Cloud based owner API Server.
    """

    # Owner API host.
    HOST = 'https://owner-api.teslamotors.com'

    # This prevents the requests + urllib3 module from creating its own user-agent.
    HEADERS = {'User-Agent': urllib3.util.SKIP_HEADER, 'Accept': 'application/json'}

    # This sets a 10 second connect and read timeout.
    TIMEOUT = 10

    # Holds the session cookie which contains the session token.
    session_cookies = None

    def __init__(self):
        """
        Initialize an Owner API instance.
        """

        # Using a session means Requests supports keep-alive.
        self.session = requests.Session()

        # Create a copy of the original header dictionary.
        self.headers = self.HEADERS.copy()

    def set_token(self, token):
        """
        Authenticates with the owner API (with a JWT).

        Args:
            token (str): JWT for authentication.
        """

        # We append an OAuth 2.0 token to future requests.
        self.headers['Authorization'] = 'Bearer ' + token

    def api_call(self, path, method='GET', data=None, json=None, response_raw=False):
        """
        Make an API call (HTML form or JSON data) to the owner API.

        Args:
            path (str): The API endpoint path.
            method (str, optional): The HTTP method for the request. Defaults to 'GET'.
            data (dict, optional): HTML form data for the request body. Defaults to None.
            json (dict, optional): JSON data for the request body. Defaults to None.
            response_raw (bool, optional): If True, return the raw response. Defaults to False.

        Returns:
            dict or str:
                JSON response if response_raw is False, raw response if response_raw is True.
        """

        # Call the owner API endpoint (optionally with form or JSON data).
        response = self.session.request(
            method=method,
            url=f'{self.HOST}{path}',
            headers=self.headers,
            data=data,
            json=json,
            timeout=self.TIMEOUT
        )

        # Bad response?
        if response.status_code != 200:
            raise ValueError(f'{response.status_code}: {response.reason}')

        # Some requests might not have JSON responses.
        if response_raw:
            # This is a raw response.
            return response.text

        # Return the JSON response.
        return response.json() if len(response.content) > 0 else None