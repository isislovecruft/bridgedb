# BridgeDB by Nick Mathewson.
# Copyright (c) 2007-2012, The Tor Project, Inc.
# See LICENSE for licensing information 

from ipaddr import IPv6Address, IPv4Address
import logging

funcs = {}

def filterAssignBridgesToRing(hmac, numRings, assignedRing):
    #XXX: ruleset should have a key unique to this function
    # ruleset ensures that the same 
    logging.debug("Creating a filter for assigning bridges to hashrings...")
    ruleset = frozenset([hmac, numRings, assignedRing]) 
    logging.debug("Filter created: %s" % ruleset)

    try: 
        return funcs[ruleset]
    except KeyError:
        def _assignBridgesToRing(bridge):
            digest = hmac(bridge.getID())
            pos = long( digest[:8], 16 )
            which = pos % numRings

            if which == assignedRing:
                return True
            else:
                logging.debug(("Bridge %s has calculated assignment %d; not "
                               "in correct ring %d.")
                              % (bridge, which, assignedRing))
                return False

        _assignBridgesToRing.__name__ = ("filterAssignBridgesToRing(%s, %s, %s)"
                                         % (hmac, numRings, assignedRing))
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

    ruleset = frozenset([methodname, addressClass])
    try:
        return funcs[ruleset]
    except KeyError:

        def _filterByTransport(bridge):
            for transport in bridge.transports:
                if isinstance(transport.address, addressClass):
                    # ignore method name case
                    if transport.methodname.lower() == methodname.lower():
                        return True
                    else:
                        logging.debug(("Transport methodname '%s' doesn't match "
                                       "requested methodname: '%s'.")
                                      % (transport.methodname, methodname))
                else:
                    logging.debug(("Transport %s has incorrect address version "
                                   "(%s).") % (transport, addressClass))
            return False

        _filterByTransport.__name__ = ("filterBridgesByTransport(%s,%s)"
                                       % (methodname, addressClass))
        setattr(_filterByTransport, "description", "transport=%s" % methodname)
        funcs[ruleset] = _filterByTransport
        return _filterByTransport

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
                logging.debug(logmsg % ( bridge.fingerprint, countryCode, ac,
                    methodname))
                return False
            return True # not blocked
        f.__name__ = "filterBridgesNotBlockedIn(%s,%s,%s)" % \
                (countryCode,methodname,addressClass)
        funcs[ruleset] = f
        return f
