# BridgeDB by Nick Mathewson.
# Copyright (c) 2007-2012, The Tor Project, Inc.
# See LICENSE for licensing information 

from ipaddr import IPv6Address, IPv4Address

def filterAssignBridgesToRing(hmac, numRings, assignedRing):
    def f(bridge):
        digest = hmac(bridge.getID())
        pos = long( digest[:8], 16 )
        which = pos % numRings
        if which == assignedRing: return True
        return False
    return f

def filterBridgesByRules(rules):
    def g(x):
        r = [f(x) for f in rules]
        if False in r: return False
        return True
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

def filterBridgesByIP6(bridge):
    try:
        if IPv6Address(bridge.ip): return True
    except ValueError:
        pass

    for k in bridge.or_addresses.keys():
        if type(k) is IPv6Address:
            return True
    return False

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
