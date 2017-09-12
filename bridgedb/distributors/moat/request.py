# -*- coding: utf-8; test-case-name: bridgedb.test.test_distributors_moat_request; -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft <isis@torproject.org> 0xA3ADB67A2CDB8B35
# :copyright: (c) 2007-2017, The Tor Project, Inc.
#             (c) 2013-2017, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""
.. py:module:: bridgedb.distributors.moat.request
    :synopsis: Classes for parsing and storing information about requests for
               bridges which are sent to the moat distributor.

bridgedb.distributors.moat.request
==================================

Classes for parsing and storing information about requests for bridges
which are sent to the moat distributor.

.. inheritance-diagram:: MoatBridgeRequest

::

  bridgedb.distributors.moat.request
   |
   |_ MoatBridgeRequest - A request for bridges which was received through
                          the moat distributor.

..
"""

from __future__ import print_function

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


class MoatBridgeRequest(bridgerequest.BridgeRequestBase):
    """We received a request for bridges through the moat distributor."""

    def __init__(self, addClientCountryCode=False):
        """Process a new bridge request received through the
        :class:`~bridgedb.distributors.moat.distributor.MoatDistributor`.

        :param bool addClientCountryCode: If ``True``, then calling
            :meth:`withoutBlockInCountry` will attempt to add the client's own
            country code, geolocated from their IP, to the ``notBlockedIn``
            countries list.
        """
        super(MoatBridgeRequest, self).__init__()
        self.addClientCountryCode = addClientCountryCode

    def withIPversion(self):
        """Determine if the request **parameters** were for bridges with IPv6
        addresses or not.

        .. note:: If the client's forwarded IP address was IPv6, then we assume
            the client wanted IPv6 bridges.
        """
        if addr.isIPAddress(self.client):
            if self.client.version == 6:
                logging.info("Moat request for bridges with IPv6 addresses.")
                self.withIPv6()

    def withoutBlockInCountry(self, data):
        """Determine which countries the bridges for this **request** should
        not be blocked in.

        If :data:`addClientCountryCode` is ``True``, the the client's own
        geolocated country code will be added to the to the
        :data:`notBlockedIn` list.

        :param dict data: The decoded data from the JSON API request.
        """
        countryCodes = data.get("unblocked", list())

        for countryCode in countryCodes:
            try:
                country = UNBLOCKED_PATTERN.match(countryCode).group()
            except (TypeError, AttributeError):
                pass
            else:
                if country:
                    self.notBlockedIn.append(country.lower())
                    logging.info("Moat request for bridges not blocked in: %r"
                                 % country)

        if self.addClientCountryCode:
            # Look up the country code of the input IP, and request bridges
            # not blocked in that country.
            if addr.isIPAddress(self.client):
                country = geo.getCountryCode(ipaddr.IPAddress(self.client))
                if country:
                    self.notBlockedIn.append(country.lower())
                    logging.info(
                        ("Moat client's bridges also shouldn't be blocked "
                         "in their GeoIP country code: %s") % country)

    def withPluggableTransportType(self, data):
        """This request included a specific Pluggable Transport identifier.

        Add any Pluggable Transport methodname found in the JSON API
        request field named "transport".

        :param dict data: The decoded data from the JSON API request.
        """
        methodname = type('')(data.get("transport", ""))

        try:
            transport = TRANSPORT_PATTERN.match(methodname).group()
        except (TypeError, AttributeError):
            pass
        else:
            if transport:
                self.transports.append(transport)
                logging.info("Moat request for transport type: %r" % transport)
