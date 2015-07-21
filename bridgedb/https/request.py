# -*- coding: utf-8; test-case-name: bridgedb.test.test_https_request; -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft <isis@torproject.org> 0xA3ADB67A2CDB8B35
# :copyright: (c) 2007-2015, The Tor Project, Inc.
#             (c) 2013-2015, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""
.. py:module:: bridgedb.https.request
    :synopsis: Classes for parsing and storing information about requests for
               bridges which are sent to the HTTPS distributor.

bridgedb.https.request
======================

Classes for parsing and storing information about requests for bridges
which are sent to the HTTPS distributor.

.. inheritance-diagram:: HTTPSBridgeRequest

::

  bridgedb.https.request
   |
   |_ HTTPSBridgeRequest - A request for bridges which was received through
                           the HTTPS distributor.

..
"""

from __future__ import print_function
from __future__ import unicode_literals

import ipaddr
import logging
import re

from bridgedb import bridgerequest
from bridgedb import geo
from bridgedb.parse import addr


#: A regular expression for matching the Pluggable Transport methodname in
#: HTTP GET request parameters.
TRANSPORT_REGEXP = "[_a-zA-Z][_a-zA-Z0-9]*"
TRANSPORT_PATTERN = re.compile(TRANSPORT_REGEXP)

UNBLOCKED_REGEXP = "[a-zA-Z]{2}"
UNBLOCKED_PATTERN = re.compile(UNBLOCKED_REGEXP)


class HTTPSBridgeRequest(bridgerequest.BridgeRequestBase):
    """We received a request for bridges through the HTTPS distributor."""

    def __init__(self, addClientCountryCode=True):
        """Process a new bridge request received through the
        :class:`~bridgedb.https.distributor.HTTPSDistributor`.

        :param bool addClientCountryCode: If ``True``, then calling
            :meth:`withoutBlockInCountry` will attempt to add the client's own
            country code, geolocated from her IP, to the ``notBlockedIn``
            countries list.
        """
        super(HTTPSBridgeRequest, self).__init__()
        self.addClientCountryCode = addClientCountryCode

    def withIPversion(self, parameters):
        """Determine if the request **parameters** were for bridges with IPv6
        addresses or not.

        .. note:: If there is an ``ipv6=`` parameter with anything non-zero
            after it, then we assume the client wanted IPv6 bridges.

        :param parameters: The :api:`twisted.web.http.Request.args`.
        """
        if parameters.get("ipv6", False):
            logging.info("HTTPS request for bridges with IPv6 addresses.")
            self.withIPv6()

    def withoutBlockInCountry(self, request):
        """Determine which countries the bridges for this **request** should
        not be blocked in.

        .. note:: Currently, a **request** for unblocked bridges is recognized
            if it contains an HTTP GET parameter ``unblocked=`` whose value is
            a comma-separater list of two-letter country codes.  Any
            two-letter country code found in the
            :api:`request <twisted.web.http.Request>` ``unblocked=`` HTTP GET
            parameter will be added to the :data:`notBlockedIn` list.

        If :data:`addClientCountryCode` is ``True``, the the client's own
        geolocated country code will be added to the to the
        :data`notBlockedIn` list.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object containing the HTTP method, full
            URI, and any URL/POST arguments and headers present.
        """
        countryCodes = request.args.get("unblocked", list())

        for countryCode in countryCodes:
            try:
                country = UNBLOCKED_PATTERN.match(countryCode).group()
            except (TypeError, AttributeError):
                pass
            else:
                if country:
                    self.notBlockedIn.append(country.lower())
                    logging.info("HTTPS request for bridges not blocked in: %r"
                                 % country)

        if self.addClientCountryCode:
            # Look up the country code of the input IP, and request bridges
            # not blocked in that country.
            if addr.isIPAddress(self.client):
                country = geo.getCountryCode(ipaddr.IPAddress(self.client))
                if country:
                    self.notBlockedIn.append(country.lower())
                    logging.info(
                        ("HTTPS client's bridges also shouldn't be blocked "
                         "in their GeoIP country code: %s") % country)

    def withPluggableTransportType(self, parameters):
        """This request included a specific Pluggable Transport identifier.

        Add any Pluggable Transport methodname found in the HTTP GET
        **parameters** to the list of ``transports``. Currently, a request for
        a transport is recognized if the request contains the
        ``'transport='`` parameter.

        :param parameters: The :api:`twisted.web.http.Request.args`.
        """
        for methodname in parameters.get("transport", list()):
            try:
                transport = TRANSPORT_PATTERN.match(methodname).group()
            except (TypeError, AttributeError):
                pass
            else:
                if transport:
                    self.transports.append(transport)
                    logging.info("HTTPS request for transport type: %r"
                                 % transport)
