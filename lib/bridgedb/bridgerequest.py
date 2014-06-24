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

    def fromJSON(json):
        """Create an instance of this class from a **json** string."""

    def toJSON():
        """Format this request into a valid JSON string."""

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

    _serialize = ['addressClass', 'transports', 'notBlockedIn', 'valid']

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

    @staticmethod
    def fromJSON(cls, json):
        """Turn **json** into an instance of this class.

        :returns: A new instance of **cls**, created from the deserialized
            attributes found in **json**, if it was parseable.
        """
        decoder = simplejson.JSONDecoder()
        decoded = None

        # Check that all attributes listed in `cls._serialize` are present:
        for attr in cls._serialize:
            if not attr in json:
                raise ValueError(
                    "JSON must contain a '%s' key to create a %s class!"
                    % (attr, cls.__class__))

        try:
            decoded = decoder.decode(json)
        except simplejson.JSONDecodeError, error:
            logging.error(error)
            return None  # XXX is this really what we want to do?

        deserialized = cls()
        try:
            for key, value in decoded.items():
                if key in cls._serialize:
                    if key == 'addressClass':
                        if str(value) == '6':
                            deserialized.withIPv6()
                        elif str(value) == '4':
                            deserialized.withIPv4()
                    elif key == 'transports':
                        for transport in key:
                            deserialized.withPluggableTransportType(transport)
                    elif key == 'notBlockedIn':
                        for unblocked in key:
                            deserialized.withoutBlockInCountry(unblocked)
                    elif key == 'valid':
                        if value == 'true':
                            deserialized.isValid(True)
        except Exception, error:
            logging.exception(error)

        return deserialized

    def toJSON(self):
        """Format this request into JSON like the following::

            { 'addressClass': '4',
              'transports': ['obfs2', 'obfs3'],
              'notBlockedIn': ['cn', 'ir'],
              'valid': 'true',}

        :rtype: str
        :returns: A JSON-formatted string serialization of this object.
        """
        encoder = simplejson.JSONEncoder()
        encoded = {}

        for attr in self._serialize:
            encoded[attr] = getattr(self, attr, None)
        # We cannot serialize `ipaddr.IPv*Address` classes:
        if isinstance(encoded['addressClass'], ipaddr.IPv6Address):
            encoded['addressClass'] = 6
        else:
            encoded['addressClass'] = 4

        json = encoder.encode(data)
        return json

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


class AnswerParameters(object):
    """Store validated settings on minimum number of Bridges with certain
    attributes which should be included in any generated subring of a
    hashring, or in an answer to a `IRequestBridges`.

    :ivar list needPorts: List of two-tuples of desired port numbers and their
        respective minimums.
    :ivar list needFlags: List of two-tuples of desired flags_ assigned to a
        Bridge by the Bridge DirAuth.

    .. _flags: https://gitweb.torproject.org/torspec.git/blob/HEAD:/dir-spec.txt#l1696
    """

    def __init__(self, needPorts=[], needFlags=[]):
        """Control the creation of subrings by including a minimum number of
        bridges which possess certain attributes.

        :type needPorts: iterable
        :param needPorts: An iterable of two-tuples. Each two tuple should
            contain ``(port, minimum)``, where ``port`` is an integer
            specifying a port number, and ``minimum`` is another integer
            specifying the minimum number of Bridges running on that ``port``
            to include in any new subring.
        :type needFlags: iterable
        :param needFlags: An iterable of two-tuples. Each two tuple should
            contain ``(flag, minimum)``, where ``flag`` is a string specifying
            an OR flag_, and ``minimum`` is an integer for the minimum number
            of Bridges which have acquired that ``flag`` to include in any new
            subring.
        :raises: An :exc:`TypeError` if an invalid port number, a minimum less
            than one, or an "unsupported" flag is given. "Stable" appears to
            be the only currently "supported" flag.
        """
        for port, count in needPorts:
            if not (1 <= port <= 65535):
                raise TypeError("Port %s out of range." % port)
            if count <= 0:
                raise TypeError("Count %s out of range." % count)
        for flag, count in needFlags:
            flag = flag.lower()
            if flag not in ["stable", "running",]:
                raise TypeError("Unsupported flag %s" % flag)
            if count <= 0:
                raise TypeError("Count %s out of range." % count)

        self.needPorts = needPorts[:]
        self.needFlags = [(flag.lower(), count) for flag, count in needFlags[:]]
