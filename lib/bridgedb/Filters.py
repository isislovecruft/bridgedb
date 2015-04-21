# BridgeDB by Nick Mathewson.
# Copyright (c) 2007-2012, The Tor Project, Inc.
# See LICENSE for licensing information 

from ipaddr import IPv6Address, IPv4Address
import logging

funcs = {}

def filterAssignBridgesToRing(hmac, numRings, assignedRing):
    logging.debug(("Creating a filter for assigning bridges to subhashring "
                   "%s-of-%s...") % (assignedRing, numRings))
    ruleset = frozenset([hmac, numRings, assignedRing]) 
    try: 
        return funcs[ruleset]
    except KeyError:
        def _assignBridgesToRing(bridge):
            digest = hmac(bridge.identity)
            pos = long( digest[:8], 16 )
            which = pos % numRings + 1

            if which == assignedRing:
                return True
            return False
        _assignBridgesToRing.__name__ = ("filterAssignBridgesToRing%sof%s"
                                         % (assignedRing, numRings))
        # XXX The `description` attribute must contain an `=`, or else
        # dumpAssignments() will not work correctly.
        setattr(_assignBridgesToRing, "description", "ring=%d" % assignedRing)
        funcs[ruleset] = _assignBridgesToRing
        return _assignBridgesToRing

def filterBridgesByRules(rules):
    ruleset = frozenset(rules)
    try: 
        return funcs[ruleset] 
    except KeyError:
        def g(x):
            r = [f(x) for f in rules]
            if False in r: return False
            return True
        setattr(g, "description", " ".join([getattr(f,'description','') for f in rules]))
        funcs[ruleset] = g
        return g  

def filterBridgesByIP4(bridge):
    try:
        if IPv4Address(bridge.address): return True
    except ValueError:
        pass

    for address, port, version in bridge.allVanillaAddresses:
        if version == 4:
            return True
    return False
setattr(filterBridgesByIP4, "description", "ip=4")

def filterBridgesByIP6(bridge):
    try:
        if IPv6Address(bridge.address): return True
    except ValueError:
        pass

    for address, port, version in bridge.allVanillaAddresses:
        if version == 6:
            return True
    return False
setattr(filterBridgesByIP6, "description", "ip=6")

def filterBridgesByTransport(methodname, addressClass=None):
    if not ((addressClass is IPv4Address) or (addressClass is IPv6Address)):
        addressClass = IPv4Address

    # Ignore case
    methodname = methodname.lower()

    ruleset = frozenset([methodname, addressClass])
    try:
        return funcs[ruleset]
    except KeyError:
        def _filterByTransport(bridge):
            for transport in bridge.transports:
                if (transport.methodname == methodname and
                    isinstance(transport.address, addressClass)):
                    return True
            return False
        _filterByTransport.__name__ = ("filterBridgesByTransport(%s,%s)"
                                       % (methodname, addressClass))
        setattr(_filterByTransport, "description", "transport=%s" % methodname)
        funcs[ruleset] = _filterByTransport
        return _filterByTransport

def filterBridgesByUnblockedTransport(methodname, countryCode=None, addressClass=None):
    """Return a filter function for :class:`~bridgedb.bridges.Bridge`s.

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
        return filterBridgesByTransport(methodname, addressClass)

    if not ((addressClass is IPv4Address) or (addressClass is IPv6Address)):
        addressClass = IPv4Address

    # Ignore case
    methodname = methodname.lower()
    countryCode = countryCode.lower()

    ruleset = frozenset([methodname, countryCode, addressClass.__name__])
    try:
        return funcs[ruleset]
    except KeyError:
        def _filterByUnblockedTransport(bridge):
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
        _filterByUnblockedTransport.__name__ = ("filterBridgesByUnblockedTransport(%s,%s,%s)"
                                                % (methodname, countryCode, addressClass))
        setattr(_filterByUnblockedTransport, "description",
                "transport=%s unblocked=%s" % (methodname, countryCode))
        funcs[ruleset] = _filterByUnblockedTransport
        return _filterByUnblockedTransport

def filterBridgesByNotBlockedIn(countryCode):
    """Return ``True`` if at least one of a bridge's (transport) bridgelines isn't
    known to be blocked in **countryCode**.

    :param str countryCode: A two-letter country code.
    :rtype: bool
    :returns: ``True`` if at least one address of the bridge isn't blocked.
        ``False`` otherwise.
    """
    countryCode = countryCode.lower()
    ruleset = frozenset([countryCode])
    try:
        return funcs[ruleset]
    except KeyError:
        def _filterByNotBlockedIn(bridge):
            if bridge.isBlockedIn(countryCode):
                return False
            return True
        _filterByNotBlockedIn.__name__ = "filterBridgesByNotBlockedIn(%s)" % countryCode
        setattr(_filterByNotBlockedIn, "description", "unblocked=%s" % countryCode)
        funcs[ruleset] = _filterByNotBlockedIn
        return _filterByNotBlockedIn
