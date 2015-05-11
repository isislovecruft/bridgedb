# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_bridgerequest ; -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2015, The Tor Project, Inc.
#             (c) 2014-2015, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________


import ipaddr
import logging

from zope.interface import implements
from zope.interface import Attribute
from zope.interface import Interface

from bridgedb.crypto import getHMACFunc
from bridgedb.filters import byIPv
from bridgedb.filters import byNotBlockedIn
from bridgedb.filters import byTransport


class IRequestBridges(Interface):
    """Interface specification of client options for requested bridges."""

    filters = Attribute(
        "A list of callables used to filter bridges from a hashring.")
    ipVersion = Attribute(
        "The IP version of bridge addresses to distribute to the client.")
    transports = Attribute(
        "A list of strings of Pluggable Transport types requested.")
    notBlockedIn = Attribute(
        "A list of two-character country codes. The distributed bridges "
        "should not be blocked in these countries.")
    valid = Attribute(
        "A boolean. Should be ``True`` if the client's request was valid.")
    client = Attribute(
        "This should be some information unique to the client making the "
        "request for bridges, such that we are able to HMAC this unique "
        "data, via getHashringPlacement(), in order to place the client "
        "into a hashring (determining which bridge addresses they get in "
        "the request response).")

    def addFilter():
        """Add a filter to the list of ``filters``."""

    def clearFilters():
        """Clear the list of ``filters``."""

    def generateFilters():
        """Build the list of callables, ``filters``, according to the current
        contents of the lists of ``transports``, ``notBlockedIn``, and the
        ``ipVersion``.
        """

    def getHashringPlacement():
        """Use some unique parameters of the client making this request to
        obtain a value which we can use to place them into one of the hashrings
        with :class:`~bridgedb.bridges.Bridge`s in it, in order to give that
        client different bridges than other clients.
        """

    def isValid():
        """Determine if the request is ``valid`` according to some parameters."""

    def withIPv4():
        """Set the ``ipVersion`` to IPv4."""

    def withIPv6():
        """Set the ``ipVersion`` to IPv6."""

    def withPluggableTransportType(typeOfPT):
        """Add this **typeOfPT** to the list of requested ``transports``."""

    def withoutBlockInCountry(countryCode):
        """Add this **countryCode** to the list of countries which distributed
        bridges should not be blocked in (``notBlockedIn``).
        """


class BridgeRequestBase(object):
    """A generic base class for storing options of a client bridge request."""

    implements(IRequestBridges)

    def __init__(self, ipVersion=None):
        self.ipVersion = ipVersion
        #: (list) A list of callables used to filter bridges from a hashring.
        self.filters = list()
        #: (list) A list of strings of Pluggable Transport types requested.
        self.transports = list()
        #: (list) A list of two-character country codes. The distributed bridges
        #: should not be blocked in these countries.
        self.notBlockedIn = list()
        #: This should be some information unique to the client making the
        #: request for bridges, such that we are able to HMAC this unique data
        #: in order to place the client into a hashring (determining which
        #: bridge addresses they get in the request response). It defaults to
        #: the string ``'default'``.
        self.client = 'default'
        #: (bool) Should be ``True`` if the client's request was valid.
        self.valid = False

    @property
    def ipVersion(self):
        """The IP version of bridge addresses to distribute to the client.

        :rtype: int
        :returns: Either ``4`` or ``6``.
        """
        return self._ipVersion

    @ipVersion.setter
    def ipVersion(self, ipVersion):
        """The IP version of bridge addresses to distribute to the client.

        :param int ipVersion: The IP address version for the bridge lines we
            should distribute in response to this client request.
        """
        if not ipVersion in (4, 6):
            ipVersion = 4
        self._ipVersion = ipVersion

    def getHashringPlacement(self, key, client=None):
        """Create an HMAC of some **client** info using a **key**.

        :param str key: The key to use for HMACing.
        :param str client: Some (hopefully unique) information about the
            client who is requesting bridges, such as an IP or email address.
        :rtype: long
        :returns: A long specifying index of the first node in a hashring to
            be distributed to the client. This value should obviously be used
            mod the number of nodes in the hashring.
        """
        if not client:
            client = self.client

        # Get an HMAC with the key of the client identifier:
        digest = getHMACFunc(key)(client)
        # Take the lower 8 bytes of the digest and convert to a long:
        position = long(digest[:8], 16)
        return position

    def isValid(self, valid=None):
        """Get or set the validity of this bridge request.

        If called without parameters, this method will return the current
        state, otherwise (if called with the **valid** parameter), it will set
        the current state of validity for this request.

        :param bool valid: If given, set the validity state of this
            request. Otherwise, get the current state.
        """
        if valid is not None:
            self.valid = bool(valid)
        return self.valid

    def withIPv4(self):
        self.ipVersion = 4

    def withIPv6(self):
        self.ipVersion = 6

    def withoutBlockInCountry(self, country):
        self.notBlockedIn.append(country.lower())

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
        self.clearFilters()

        pt = self.justOnePTType()
        msg = ("Adding a filter to %s for %s for IPv%d"
               % (self.__class__.__name__, self.client, self.ipVersion))

        if self.notBlockedIn:
            for country in self.notBlockedIn:
                logging.info("%s %s bridges not blocked in %s..." %
                             (msg, pt or "vanilla", country))
                self.addFilter(byNotBlockedIn(country, pt, self.ipVersion))
        elif pt:
            logging.info("%s %s bridges..." % (msg, pt))
            self.addFilter(byTransport(pt, self.ipVersion))
        else:
            logging.info("%s bridges..." % msg)
            self.addFilter(byIPv(self.ipVersion))
