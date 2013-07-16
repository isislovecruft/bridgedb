# BridgeDB by Nick Mathewson.
# Copyright (c) 2007-2012, The Tor Project, Inc.
# See LICENSE for licensing information 

from ipaddr import IPv6Address, IPv4Address

import bridgedb.log as log


funcs = {}

def filterAssignBridgesToRing(hmac, numRings, assignedRing):
    #XXX: ruleset should have a key unique to this function
    # ruleset ensures that the same 
    ruleset = frozenset([hmac, numRings, assignedRing]) 
    try: 
        return funcs[ruleset]
    except KeyError:
        def f(bridge):
            digest = hmac(bridge.getID())
            pos = long( digest[:8], 16 )
            which = pos % numRings
            if which == assignedRing: return True
            return False
        f.__name__ = "filterAssignBridgesToRing(%s, %s, %s)" % (hmac, numRings,
                                                                 assignedRing)
        setattr(f, "description", "ring=%d" % assignedRing)
        funcs[ruleset] = f
        return f

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
        if IPv4Address(bridge.ip): return True
    except ValueError:
        pass

    for k in bridge.or_addresses.keys():
        if type(k) is IPv4Address:
            return True
    return False
setattr(filterBridgesByIP4, "description", "ip=4")

def filterBridgesByIP6(bridge):
    try:
        if IPv6Address(bridge.ip): return True
    except ValueError:
        pass

    for k in bridge.or_addresses.keys():
        if type(k) is IPv6Address:
            return True
    return False
setattr(filterBridgesByIP6, "description", "ip=6")

def filterBridgesByOnlyIP4(bridge):
    for k in bridge.or_addresses.keys():
        if type(k) is IPv6Address:
            return False
    if type(k) is IPv4Address:
        return True
    return False

def filterBridgesByOnlyIP6(bridge):
    for k in bridge.or_addresses.keys():
        if type(k) is IPv4Address:
            return False
    if type(k) is IPv6Address:
        return True
    return False

def filterBridgesByTransport(methodname, addressClass=None):
    if addressClass is None: addressClass = IPv4Address
    assert (addressClass) in (IPv4Address, IPv6Address)
    ruleset = frozenset([methodname, addressClass])
    try:
        return funcs[ruleset]
    except KeyError:
        def f(bridge):
            for transport in bridge.transports:
                # ignore method name case
                if isinstance(transport.address, addressClass) and \
                transport.methodname.lower() == methodname.lower(): return True
            return False
        f.__name__ = "filterBridgesByTransport(%s,%s)" % (methodname,
                addressClass)
        setattr(f, "description", "transport=%s"%methodname)
        funcs[ruleset] = f
        return f

def filterBridgesByNotBlockedIn(countryCode, addressClass=None, methodname=None):
    """ if at least one address:port of the selected addressClass and
    (optional) transport type is not blocked in countryCode, return True
    """
    # default to IPv4 if not specified
    if addressClass is None: addressClass = IPv4Address
    assert (addressClass) in (IPv4Address, IPv6Address)
    ruleset = frozenset([countryCode, addressClass, methodname])
    try:
        return funcs[ruleset]
    except KeyError:
        def f(bridge):
            if bridge.isBlocked(countryCode, addressClass, methodname):
                if addressClass is IPv4Address: ac = "IPv4"
                else: ac = "IPv6"
                logmsg = "Removing %s from set of results for country"
                logmsg += " '%s' with address class %s and transport %s"
                log.debug(logmsg % ( bridge.fingerprint, countryCode, ac,
                    methodname))
                return False
            return True # not blocked
        f.__name__ = "filterBridgesNotBlockedIn(%s,%s,%s)" % \
                (countryCode,methodname,addressClass)
        funcs[ruleset] = f
        return f
