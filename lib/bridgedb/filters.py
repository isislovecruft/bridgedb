# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_filters ; -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Nick Mathewson <nickm@torproject.org>
#           Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2015, The Tor Project, Inc.
#             (c) 2013-2015, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

import logging

from ipaddr import IPv4Address
from ipaddr import IPv6Address

from bridgedb.parse.addr import isIPv4
from bridgedb.parse.addr import isIPv6


_cache = {}


def byIPv4(bridge):
    """Return ``True`` if at least one of the **bridge**'s addresses is IPv4.

    :type bridge: :class:`~bridgedb.bridges.Bridge`.
    :param bridge: The bridge to check.
    """
    if isIPv4(bridge.address):
        return True
    else:
        for address, port, version in bridge.allVanillaAddresses:
            if version == 4 or isIPv4(address):
                return True
    return False
setattr(byIPv4, "description", "ip=4")

def byIPv6(bridge):
    """Return ``True`` if at least one of the **bridge**'s addresses is IPv6.

    :type bridge: :class:`~bridgedb.bridges.Bridge`.
    :param bridge: The bridge to check.
    """
    if isIPv6(bridge.address):
        return True
    else:
        for address, port, version in bridge.allVanillaAddresses:
            if version == 6 or isIPv6(address):
                return True
            logging.debug("%s is not ipv6" % address)
    return False
setattr(byIPv6, "description", "ip=6")

def assignBridgesToSubring(hmac, assigned, total):
    """Create a filter function which filters for only the bridges which fall
    into the same **assigned** subhashring (based on the results of an **hmac**
    function).

    :type hmac: callable
    :param hmac: An HMAC function, i.e. as returned from
        :func:`bridgedb.crypto.getHMACFunc`.
    :param int assigned: The subring number that we wish to draw bridges from.
        For example, if a user is assigned to subring 2of3 based on their IP
        address, then this function should only return bridges which would
        also be assigned to subring 2of3.
    :param int total: The total number of subrings.
    :rtype: callable
    :returns: A filter function for :class:`~bridgedb.bridges.Bridge`s.
    """
    logging.debug(("Creating a filter for assigning bridges to subhashring "
                   "%s-of-%s...") % (assigned, total))
    ruleset = frozenset([hmac, "%sof%s" % (assigned, total)])
    try:
        return _cache[ruleset]
    except KeyError:
        def _assignBridgesToSubring(bridge):
            position = long(hmac(bridge.identity)[:8], 16)
            which = (position % total) + 1
            return True if which == assigned else False
        _assignBridgesToSubring.__name__ = ("assignBridgesToSubring%sof%s"
                                            % (assigned, total))
        # The `description` attribute must contain an `=`, or else
        # dumpAssignments() will not work correctly.
        setattr(_assignBridgesToSubring, "description", "ring=%d" % assigned)
        _cache[ruleset] = _assignBridgesToSubring
        return _assignBridgesToSubring

def byFilters(filtres):
    """Returns a filter which filters by multiple **filtres**.

    :type filtres: list
    :param filtres: A list (or other iterable) of callables which some
        :class:`~bridgedb.bridges.Bridge`s should be filtered according to.
    :rtype: callable
    :returns: A filter function for :class:`~bridgedb.bridges.Bridge`s.
    """
    ruleset = frozenset(filtres)
    try:
        return _cache[ruleset]
    except KeyError:
        def _byFilters(bridge):
            results = [f(bridge) for f in filtres]
            if False in results:
                return False
            return True
        setattr(_byFilters, "description",
                " ".join([getattr(f, "description", "") for f in filtres]))
        _cache[ruleset] = _byFilters
        return _byFilters

def byNotBlockedIn(countryCode):
    """Returns a filter function for :class:`~bridgedb.bridges.Bridge`s.

    The returned filter function should be called on a
    :class:`~bridgedb.bridges.Bridge`.  It returns ``True`` if any of the
    ``Bridge``'s addresses or :class:`~bridgedb.bridges.PluggableTransport`
    addresses aren't blocked in **countryCode**.  See
    :meth:`~bridgedb.bridges.Bridge.isBlockedIn`.

    :param str countryCode: A two-letter country code.
    :rtype: callable
    :returns: A filter function for :class:`~bridgedb.bridges.Bridge`s.
    """
    countryCode = countryCode.lower()
    ruleset = frozenset([countryCode])
    try:
        return _cache[ruleset]
    except KeyError:
        def _byNotBlockedIn(bridge):
            if bridge.isBlockedIn(countryCode):
                return False
            return True
        _byNotBlockedIn.__name__ = "byNotBlockedIn(%s)" % countryCode
        setattr(_byNotBlockedIn, "description", "unblocked=%s" % countryCode)
        _cache[ruleset] = _byNotBlockedIn
        return _byNotBlockedIn

def byTransport(methodname, addressClass=None):
    """Returns a filter function for :class:`~bridgedb.bridges.Bridge`s.

    The returned filter function should be called on a
    :class:`~bridgedb.bridges.Bridge`.  It returns ``True`` if the ``Bridge``
    has a :class:`~bridgedb.bridges.PluggableTransport` such that:

      1. The :data:`~bridge.bridges.PluggableTransport.methodname` matches
         **methodname**, and

      2. The :data:`~bridgedb.bridges.PluggableTransport.address`` is an
         instance of **addressClass**.

    :param str methodname: A Pluggable Transport
        :data:`~bridge.bridges.PluggableTransport.methodname`.
    :type addressClass: ``ipaddr.IPAddress``
    :param addressClass: The IP version that the ``Bridge``'s
        ``PluggableTransport``
        :data:`~bridgedb.bridges.PluggableTransport.address`` should have.
    :rtype: callable
    :returns: A filter function for :class:`~bridgedb.bridges.Bridge`s.
    """
    if not ((addressClass is IPv4Address) or (addressClass is IPv6Address)):
        addressClass = IPv4Address

    # Ignore case
    methodname = methodname.lower()

    ruleset = frozenset([methodname, addressClass.__name__])
    try:
        return _cache[ruleset]
    except KeyError:
        def _byTransport(bridge):
            for transport in bridge.transports:
                if (transport.methodname == methodname and
                    isinstance(transport.address, addressClass)):
                    return True
            return False
        _byTransport.__name__ = "byTransport(%s,%s)" % (methodname, addressClass)
        setattr(_byTransport, "description", "transport=%s" % methodname)
        _cache[ruleset] = _byTransport
        return _byTransport

def byTransportNotBlockedIn(methodname, countryCode=None, addressClass=None):
    """Returns a filter function for :class:`~bridgedb.bridges.Bridge`s.

    The returned filter function should be called on a
    :class:`~bridgedb.bridges.Bridge`.  It returns ``True`` if the ``Bridge``
    has a :class:`~bridgedb.bridges.PluggableTransport` such that:

      1. The :data:`~bridge.bridges.PluggableTransport.methodname` matches
         **methodname**,

      2. The :data:`~bridgedb.bridges.PluggableTransport.address`` is an
         instance of **addressClass**, and isn't known to be blocked in
         **countryCode**.

    :param str methodname: A Pluggable Transport
        :data:`~bridge.bridges.PluggableTransport.methodname`.
    :type countryCode: str or ``None``
    :param countryCode: A two-letter country code which the filtered
        :class:`PluggableTransport`s should not be blocked in.
    :type addressClass: ``ipaddr.IPAddress``
    :param addressClass: The IP version that the ``Bridge``'s
        ``PluggableTransport``
        :data:`~bridgedb.bridges.PluggableTransport.address`` should have.
    :rtype: callable
    :returns: A filter function for :class:`~bridgedb.bridges.Bridge`s.
    """
    if not countryCode:
        return byTransport(methodname, addressClass)

    if not ((addressClass is IPv4Address) or (addressClass is IPv6Address)):
        addressClass = IPv4Address

    # Ignore case
    methodname = methodname.lower()
    countryCode = countryCode.lower()

    ruleset = frozenset([methodname, countryCode, addressClass.__name__])
    try:
        return _cache[ruleset]
    except KeyError:
        def _byTransportNotBlockedIn(bridge):
            # Since bridge.transportIsBlockedIn() will return True if the
            # bridge has that type of transport AND that transport is blocked,
            # we can "fail fast" here by doing this faster check before
            # iterating over all the transports testing for the other
            # conditions.
            if bridge.transportIsBlockedIn(countryCode, methodname):
                return False
            else:
                for transport in bridge.transports:
                    if (transport.methodname == methodname and
                        isinstance(transport.address, addressClass)):
                        return True
            return False
        _byTransportNotBlockedIn.__name__ = ("byTransportNotBlockedIn(%s,%s,%s)"
                                             % (methodname, countryCode, addressClass))
        setattr(_byTransportNotBlockedIn, "description",
                "transport=%s unblocked=%s" % (methodname, countryCode))
        _cache[ruleset] = _byTransportNotBlockedIn
        return _byTransportNotBlockedIn
