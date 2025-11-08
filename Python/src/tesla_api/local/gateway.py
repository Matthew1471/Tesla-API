#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of Tesla-API <https://github.com/Matthew1471/Tesla-API>
# Copyright (C) 2023 Matthew1471!
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
Tesla-API Gateway Module
This module provides classes and methods for interacting locally with an Tesla® Gateway.
It supports maintaining an authenticated session between API calls and handles communication with
the gateway.
"""

# Third party library; "pip install requests" if getting import errors.
import requests

# Disable the warning about insecure HTTPS requests (and skip automatic user-agent header).
import urllib3


class Gateway:
    """
    A class to talk locally to Tesla®'s Gateway.
    This supports maintaining an authenticated session between API calls.
    """

    # This prevents the requests + urllib3 module from creating its own user-agent.
    HEADERS = {'User-Agent': urllib3.util.SKIP_HEADER, 'Accept': 'application/json'}

    # This sets a 1 minute connect and read timeout.
    TIMEOUT = 60

    def __init__(self, host=None):
        """
        Initialize an Tesla® Gateway instance.

        Args:
            host (str, optional):
                The host URL of the Tesla® Gateway (including the protocol).
                Defaults to 'https://teg'.

        Notes:
            - HTTPS requests will be made with reduced security.
        """

        # The Gateway host (or if the network supports mDNS, "https://teg").
        self.host = 'https://teg' if host is None else host

        # Using a session means Requests supports keep-alive.
        self.session = requests.Session()

        # Disable the warnings about making an insecure request.
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Perform no verification of the remote host or the security of the connection.
        self.session.verify = False

    def login(self, password, username='customer'):
        """
        Authenticates with the Gateway (with a email and password).
        The Gateway does not require Internet connectivity.

        Args:
            email (str): The e-mail address for authentication.
            password (str): The password for authentication.

        Returns:
            bool: True if login is successful, False otherwise.
        """

        # Returns a "AuthCookie" (access token) cookie if successful which then validates access
        # to the Gateway.
        response = self.session.post(
            url=f'{self.host}/api/login/Basic',
            json={'username': username, 'password': password},
            headers=Gateway.HEADERS,
            timeout=Gateway.TIMEOUT
        )

        # Check the response is positive.
        return response.status_code == 200

    def api_call(self, path, method='GET', data=None, json=None):
        """
        Make an API call to the Gateway.

        Args:
            path (str): The API endpoint path.
            method (str, optional): The HTTP method for the request. Defaults to 'GET'.
            data (byte, optional): Binary data for the request body. Defaults to None.
            json (dict, optional): JSON data for the request body. Defaults to None.

        Returns:
            dict: JSON response.
        """

        # Call the Gateway API endpoint (optionally with JSON data).
        response = self.session.request(
            method=method,
            url=f'{self.host}{path}',
            headers=Gateway.HEADERS,
            data=data,
            json=json,
            timeout=Gateway.TIMEOUT
        )

        # Has the session expired?
        if response.status_code == 401:
            raise ValueError(response.reason)

        # TED-API requests have protobuf responses.
        if data and len(response.content) > 0:
            return response.content

        # Return the JSON response.
        return response.json() if len(response.content) > 0 else None

    @staticmethod
    def scale_soe(percentage):
        """
        Scale the battery percentage to reserve a 5% buffer.

        The Tesla® App always shows the State Of Energy with a 5% reduction.
        It needs this 5% buffer to keep the Gateway and Powerwall® computers powered
        when the grid is not available.

        Args:
            percentage (float): The battery percentage without a 5% buffer.

        Returns:
            float:
                The battery percentage with a 5% number.
        """

        # Tesla® App always reserves 5% of battery.
        return (percentage - 5) / 0.95
