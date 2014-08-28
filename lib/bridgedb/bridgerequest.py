# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_bridgerequest ; -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2014, The Tor Project, Inc.
#             (c) 2014, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________


import logging

import ipaddr

from zope.interface import implements
from zope.interface import Attribute
from zope.interface import Interface

from bridgedb import Filters


class IRequestBridges(Interface):
    """Interface specification of client options for requested bridges."""

    addressClass = Attribute(
        "The IP version of bridge addresses to distribute to the client.")
    filters = Attribute(
        "A list of callables used to filter bridges from a hashring.")
    transports = Attribute(
        "A list of strings of Pluggable Transport types requested.")
    notBlockedIn = Attribute(
        "A list of 2-4 letter country codes. The distributed bridges should "
        "not be blocked in these countries.")
    valid = Attribute(
        "A boolean. Should be ``True`` if the client's request was valid.")

    def addFilter():
        """Add a filter to the list of ``filters``."""

    def clearFilters():
        """Clear the list of ``filters``."""

    def generateFilters():
        """Build the list of callables, ``filters``, according to the current
        contents of the lists of ``transports``, ``notBlockedIn``, and the
        ``addressClass``.
        """

    def isValid():
        """Determine if the request is ``valid`` according to some parameters."""

    def withIPv4():
        """Set the ``addressClass`` to IPv4."""

    def withIPv6():
        """Set the ``addressClass`` to IPv6."""

    def withPluggableTransportType(typeOfPT):
        """Add this **typeOfPT** to the list of requested ``transports``."""

    def withoutBlockInCountry(countryCode):
        """Add this **countryCode** to the list of countries which distributed
        bridges should not be blocked in (``notBlockedIn``).
        """


class BridgeRequestBase(object):
    """A generic base class for storing options of a client bridge request."""

    implements(IRequestBridges)

    def __init__(self, addressClass=None):
        self.addressClass = addressClass
        if not isinstance(self.addressClass,
                          (ipaddr.IPv4Address, ipaddr.IPv6Address)):
            self.addressClass = ipaddr.IPv4Address
        self.filters = list()
        self.transports = list()
        self.notBlockedIn = list()
        self.valid = False

    def isValid(self):
        pass

    def withIPv4(self):
        self.addressClass = ipaddr.IPv4Address

    def withIPv6(self):
        self.addressClass = ipaddr.IPv6Address

    def withoutBlockInCountry(self, country):
        self.notBlockedIn.append(country)

    def withPluggableTransportType(self, pt):
        self.transports.append(pt)

    def addFilter(self, filtre):
        self.filters.append(filtre)

    def clearFilters(self):
        self.filters = []

    def justOnePTType(self):
        """Get just one bridge PT type at a time!"""
        ptType = None
        try:
            ptType = self.transports[-1]  # Use the last PT requested
        except IndexError:
            logging.debug("No pluggable transports were requested.")
        return ptType

    def generateFilters(self):
        if self.addressClass is ipaddr.IPv6Address:
            self.addFilter(Filters.filterBridgesByIP6)
        else:
            self.addFilter(Filters.filterBridgesByIP4)

        transport = self.justOnePTType()
        if transport:
            self.clearFilters()
            self.addFilter(Filters.filterBridgesByTransport(transport,
                                                            self.addressClass))
        for country in self.notBlockedIn:
            self.addFilter(Filters.filterBridgesByNotBlockedIn(country,
                                                               self.addressClass,
                                                               transport))
