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

"""Functions for filtering :class:`Bridges <bridgedb.bridges.Bridge>`."""

import logging

from ipaddr import IPv4Address
from ipaddr import IPv6Address

from bridgedb.parse.addr import isIPv


_cache = {}


def bySubring(hmac, assigned, total):
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
    :returns: A filter function for :class:`Bridges <bridgedb.bridges.Bridge>`.
    """
    logging.debug(("Creating a filter for assigning bridges to subhashring "
                   "%s-of-%s...") % (assigned, total))

    name = "-".join([str(hmac("")[:8]).encode('hex'),
                     str(assigned), "of", str(total)])
    try:
        return _cache[name]
    except KeyError:
        def _bySubring(bridge):
            position = int(hmac(bridge.identity)[:8], 16)
            which = (position % total) + 1
            return True if which == assigned else False
        # The `description` attribute must contain an `=`, or else
        # dumpAssignments() will not work correctly.
        setattr(_bySubring, "description", "ring=%d" % assigned)
        _bySubring.__name__ = ("bySubring%sof%s" % (assigned, total))
        _bySubring.name = name
        _cache[name] = _bySubring
        return _bySubring

def byFilters(filtres):
    """Returns a filter which filters by multiple **filtres**.

    :param list filtres: A list (or other iterable) of callables which some
        :class:`Bridges <bridgedb.bridges.Bridge>` should be filtered
        according to.
    :rtype: callable
    :returns: A filter function for :class:`Bridges <bridgedb.bridges.Bridge>`.
    """
    name = []
    for filtre in filtres:
        name.extend(filtre.name.split(" "))
    name = " ".join(set(name))

    try:
        return _cache[name]
    except KeyError:
        def _byFilters(bridge):
            results = [f(bridge) for f in filtres]
            if False in results:
                return False
            return True
        setattr(_byFilters, "description",
                " ".join([getattr(f, "description", "") for f in filtres]))
        _byFilters.name = name
        _cache[name] = _byFilters
        return _byFilters

def byIPv(ipVersion=None):
    """Return ``True`` if at least one of the **bridge**'s addresses has the
    specified **ipVersion**.

    :param int ipVersion: Either ``4`` or ``6``.
    """
    if not ipVersion in (4, 6):
        ipVersion = 4

    name = "ipv%d" % ipVersion
    try:
        return _cache[name]
    except KeyError:
        def _byIPv(bridge):
            """Determine if the **bridge** has an IPv{0} address.

            :type bridge: :class:`bridgedb.bridges.Bridge`
            :param bridge: A bridge to filter.
            :rtype: bool
            :returns: ``True`` if the **bridge** has an address with the
                correct IP version; ``False`` otherwise.
            """
            if isIPv(ipVersion, bridge.address):
                return True
            else:
                for address, port, version in bridge.allVanillaAddresses:
                    if version == ipVersion or isIPv(ipVersion, address):
                        return True
            return False
        setattr(_byIPv, "description", "ip=%d" % ipVersion)
        _byIPv.__name__ = "byIPv%d()" % ipVersion
        _byIPv.func_doc = _byIPv.func_doc.format(ipVersion)
        _byIPv.name = name
        _cache[name] = _byIPv
        return _byIPv

byIPv4 = byIPv(4)
byIPv6 = byIPv(6)

def byTransport(methodname=None, ipVersion=None):
    """Returns a filter function for a :class:`~bridgedb.bridges.Bridge`.

    The returned filter function should be called on a
    :class:`~bridgedb.bridges.Bridge`.  It returns ``True`` if the
    :class:`~bridgedb.bridges.Bridge` has a
    :class:`~bridgedb.bridges.PluggableTransport` such that:

    1. The :data:`methodname <bridgedb.bridges.PluggableTransport.methodname>`
       matches **methodname**, and,

    2. The :attr:`bridgedb.bridges.PluggableTransport.address.version`
       equals the **ipVersion**.

    :param str methodname: A Pluggable Transport
        :data:`~bridgedb.bridges.PluggableTransport.methodname`.
    :param int ipVersion: Either ``4`` or ``6``. The IP version that the
        ``Bridge``'s ``PluggableTransport``
        :attr:`address <bridgedb.bridges.PluggableTransport.address>` should
        have.
    :rtype: callable
    :returns: A filter function for :class:`Bridges <bridgedb.bridges.Bridge>`.
    """
    if not ipVersion in (4, 6):
        ipVersion = 4
    if not methodname:
        return byIPv(ipVersion)

    methodname = methodname.lower()
    name = "transport-%s ipv%d" % (methodname, ipVersion)

    try:
        return _cache[name]
    except KeyError:
        def _byTransport(bridge):
            for transport in bridge.transports:
                if transport.methodname == methodname:
                    if transport.address.version == ipVersion:
                        return True
            return False
        setattr(_byTransport, "description", "transport=%s" % methodname)
        _byTransport.__name__ = "byTransport(%s,%s)" % (methodname, ipVersion)
        _byTransport.name = name
        _cache[name] = _byTransport
        return _byTransport

def byNotBlockedIn(countryCode=None, methodname=None, ipVersion=4):
    """Returns a filter function for :class:`Bridges <bridgedb.bridges.Bridge>`.

    If a Pluggable Transport **methodname** was not specified, the returned
    filter function returns ``True`` if any of the ``Bridge``'s addresses or
    :class:`~bridgedb.bridges.PluggableTransport` addresses aren't blocked in
    **countryCode**.  See :meth:`~bridgedb.bridges.Bridge.isBlockedIn`.

    Otherwise, if a Pluggable Transport **methodname** was specified, it
    returns ``True`` if the :class:`~bridgedb.bridges.Bridge` has a
    :class:`~bridgedb.bridges.PluggableTransport` such that:

    1. The :data:`methodname <bridgedb.bridges.PluggableTransport.methodname>`
       matches **methodname**,

    2. The :attr:`bridgedb.bridges.PluggableTransport.address.version`
       equals the **ipVersion**, and,

    3. The :class:`~bridgedb.bridges.PluggableTransport`.
       :attr:`address <bridgedb.bridges.PluggableTransport.address>` isn't
       known to be blocked in **countryCode**.

    :type countryCode: str or ``None``
    :param countryCode: A two-letter country code which the filtered
        :class:`PluggableTransports <bridgedb.bridges.PluggableTransport>`
        should not be blocked in.
    :param str methodname: A Pluggable Transport
        :data:`methodname <bridgedb.bridges.PluggableTransport.methodname>`.
    :param int ipVersion: Either ``4`` or ``6``. The IP version that the
        ``PluggableTransports``'s addresses should have.
    :rtype: callable
    :returns: A filter function for :class:`Bridges <bridgedb.bridges.Bridge>`.
    """
    if not ipVersion in (4, 6):
        ipVersion = 4
    if not countryCode:
        return byTransport(methodname, ipVersion)

    methodname = methodname.lower() if methodname else methodname
    countryCode = countryCode.lower()

    name = []
    if methodname:
        name.append("transport-%s" % methodname)
    name.append("ipv%d" % ipVersion)
    name.append("not-blocked-in-%s" % countryCode)
    name = " ".join(name)

    try:
        return _cache[name]
    except KeyError:
        def _byNotBlockedIn(bridge):
            if not methodname:
                return not bridge.isBlockedIn(countryCode)
            elif methodname == "vanilla":
                if bridge.address.version == ipVersion:
                    if not bridge.addressIsBlockedIn(countryCode,
                                                     bridge.address,
                                                     bridge.orPort):
                        return True
            else:
                # Since bridge.transportIsBlockedIn() will return True if the
                # bridge has that type of transport AND that transport is
                # blocked, we can "fail fast" here by doing this faster check
                # before iterating over all the transports testing for the
                # other conditions.
                if bridge.transportIsBlockedIn(countryCode, methodname):
                    return False
                else:
                    for transport in bridge.transports:
                        if transport.methodname == methodname:
                            if transport.address.version == ipVersion:
                                return True
            return False
        setattr(_byNotBlockedIn, "description", "unblocked=%s" % countryCode)
        _byNotBlockedIn.__name__ = ("byTransportNotBlockedIn(%s,%s,%s)"
                                    % (methodname, countryCode, ipVersion))
        _byNotBlockedIn.name = name
        _cache[name] = _byNotBlockedIn
        return _byNotBlockedIn
