# BridgeDB by Nick Mathewson.
# Copyright (c) 2007, The Tor Project, Inc.
# See LICENSE for licensing informatino

import bridgedb.Bridges

import logging
import re
import socket

def uniformMap(ip):
    """Map an IP to an arbitrary 'area' string, such that any two /24 addresses
       get the same string.

    >>> uniformMap('1.2.3.4')
    '1.2.3'
    """
    return ".".join( ip.split(".")[:3] )

class IPBasedDistributor(bridgedb.Bridges.BridgeHolder):
    def __init__(self, areaMapper, nClusters, key):
        self.areaMapper = areaMapper

        self.rings = []
        for n in xrange(nClusters):
            key1 = bridgedb.Bridges.get_hmac(key, "Order-Bridges-In-Ring-%d"%n)
            self.rings.append( bridgedb.Bridges.BridgeRing(key1) )
            self.rings[-1].name = "IP ring %s"%len(self.rings)

        key2 = bridgedb.Bridges.get_hmac(key, "Assign-Bridges-To-Rings")
        self.splitter = bridgedb.Bridges.FixedBridgeSplitter(key2, self.rings)

        key3 = bridgedb.Bridges.get_hmac(key, "Order-Areas-In-Rings")
        self.areaOrderHmac = bridgedb.Bridges.get_hmac_fn(key3, hex=False)

        key4 = bridgedb.Bridges.get_hmac(key, "Assign-Areas-To-Rings")
        self.areaClusterHmac = bridgedb.Bridges.get_hmac_fn(key4, hex=True)

    def insert(self, bridge):
        self.splitter.insert(bridge)

    def getBridgesForIP(self, ip, epoch, N=1):
        if not len(self.splitter):
            return []

        area = self.areaMapper(ip)

        # Which bridge cluster should we look at?
        h = int( self.areaClusterHmac(area)[:8], 16)
        clusterNum = h % len(self.rings)
        ring = self.rings[clusterNum]
        # If a ring is empty, consider the next.
        while not len(ring):
            clusterNum = (clusterNum + 1) % len(self.rings)
            ring = self.rings[clusterNum]

        # Now get the bridge.
        pos = self.areaOrderHmac("<%s>%s" % (epoch, area))
        return ring.getBridges(pos, N)


# These characters are the ones that RFC2822 allows.
#ASPECIAL = '!#$%&*+-/=?^_`{|}~'
#ASPECIAL += "\\\'"

# These are the ones we're pretty sure we can handle right.
ASPECIAL = '-_+/=_~'
ACHAR = r'[\w%s]' % "".join("\\%s"%c for c in ASPECIAL)
DOTATOM = r'%s+(?:\.%s+)*'%(ACHAR,ACHAR)
DOMAIN = r'\w+(?:\.\w+)*'
ADDRSPEC = r'(%s)\@(%s)'%(DOTATOM, DOMAIN)

SPACE_PAT = re.compile(r'\s+')
ADDRSPEC_PAT = re.compile(ADDRSPEC)

class BadEmail(Exception):
    def __init__(self, msg, email):
        Exception.__init__(self, msg)
        self.email = email

class UnsupportedDomain(BadEmail):
    pass

def extractAddrSpec(addr):
    orig_addr = addr
    addr = SPACE_PAT.sub(' ', addr)
    addr = addr.strip()
    # Only works on usual-form addresses; raises BadEmail on weird
    # address form.  That's okay, since we'll only get those when
    # people are trying to fool us.
    if '<' in addr:
        # Take the _last_ index of <, so that we don't need to bother
        # with quoting tricks.
        idx = addr.rindex('<')
        addr = addr[idx:]
        m = re.search(r'<([^>]*)>', addr)
        if m is None:
            raise BadEmail("Couldn't extract address spec", orig_addr)
        addr = m.group(1)

    # At this point, addr holds a putative addr-spec.  We only allow the
    # following form:
    #   addr-spec = local-part "@" domain
    #   local-part = dot-atom
    #   domain = dot-atom
    #
    # In particular, we are disallowing: obs-local-part, obs-domain,
    # comment, obs-FWS,
    #
    # Other forms exist, but none of the incoming services we recognize
    # support them.
    addr = addr.replace(" ", "")
    m = ADDRSPEC_PAT.match(addr)
    if not m:
        raise BadEmail("Bad address spec format", orig_addr)
    localpart, domain = m.groups()
    return localpart, domain

def normalizeEmail(addr, domainmap):
    addr = addr.lower()
    localpart, domain = extractAddrSpec(addr)
    if domainmap is not None:
        domain = domainmap.get(domain, None)
        if domain is None:
            raise UnsupportedDomain("Domain not supported", addr)
    idx = localpart.find('+')
    if idx >= 0:
        localpart = localpart[:idx]
    return "%s@%s"%(localpart, domain)

class EmailBasedDistributor(bridgedb.Bridges.BridgeHolder):
    def __init__(self, key, store, domainmap):

        key1 = bridgedb.Bridges.get_hmac(key, "Map-Addresses-To-Ring")
        self.emailHmac = bridgedb.Bridges.get_hmac_fn(key1, hex=False)

        key2 = bridgedb.Bridges.get_hmac(key, "Order-Bridges-In-Ring")
        self.ring = bridgedb.Bridges.BridgeRing(key2)
        self.ring.name = "email ring"
        self.store = store
        self.domainmap = domainmap

    def insert(self, bridge):
        self.ring.insert(bridge)

    def getBridgesForEmail(self, emailaddress, epoch, N=1):
        emailaddress = normalizeEmail(emailaddress, self.domainmap)
        if emailaddress is None:
            return [] #XXXX raise an exception.
        if self.store.has_key(emailaddress):
            result = []
            ids_str = self.store[emailaddress]
            ids = bridgedb.Bridges.chopString(ids_str, bridgedb.Bridges.ID_LEN)
            logging.info("We've seen %r before. Sending the same %d bridges"
                         " as last time", emailaddress, len(ids))
            for id in ids:
                b = self.ring.getBridgeByID(id)
                if b != None:
                    result.append(b)
            return result

        pos = self.emailHmac("<%s>%s" % (epoch, emailaddress))
        result = self.ring.getBridges(pos, N)
        memo = "".join(b.getID() for b in result)
        self.store[emailaddress] = memo
        return result

if __name__ == '__main__':
    import sys
    for line in sys.stdin:
        line = line.strip()
        if line.startswith("From: "):
            line = line[6:]
        try:
            normal = normalizeEmail(line, None)
            print normal
        except BadEmail, e:
            print line, e
