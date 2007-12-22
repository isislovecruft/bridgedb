# BridgeDB by Nick Mathewson.
# Copyright (c) 2007, The Tor Project, Inc.
# See LICENSE for licensing information

"""
This module has functions to decide which bridges to hand out to whom.
"""

import bridgedb.Bridges

import logging
import re

def uniformMap(ip):
    """Map an IP to an arbitrary 'area' string, such that any two /24 addresses
       get the same string.

    >>> uniformMap('1.2.3.4')
    '1.2.3'
    """
    return ".".join( ip.split(".")[:3] )

class IPBasedDistributor(bridgedb.Bridges.BridgeHolder):
    """Object that hands out bridges based on the IP address of an incoming
       request and the current time period.
    """
    ## Fields:
    ##    areaMapper -- a function that maps an IP address to a string such
    ##        that addresses mapping to the same string are in the same "area".
    ##    rings -- a list of BridgeRing objects.  Every bridge goes into one
    ##        of these rings, and every area is associated with one.
    ##    splitter -- a FixedBridgeSplitter to assign bridges into the
    ##        rings of this distributor.
    ##    areaOrderHmac -- an hmac function used to order areas within rings.
    ##    areaClusterHmac -- an hmac function used to assign areas to rings.
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
        """Assign a bridge to this distributor."""
        self.splitter.insert(bridge)

    def getBridgesForIP(self, ip, epoch, N=1):
        """Return a list of bridges to give to a user.
           ip -- the user's IP address, as a dotted quad.
           epoch -- the time period when we got this request.  This can
               be any string, so long as it changes with every period.
           N -- the number of bridges to try to give back.
        """
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
    """Exception raised when we get a bad email address."""
    def __init__(self, msg, email):
        Exception.__init__(self, msg)
        self.email = email

class UnsupportedDomain(BadEmail):
    """Exception raised when we get an email address from a domain we
       don't know."""
    pass

def extractAddrSpec(addr):
    """Given an email From line, try to extract and parse the addrspec
       portion.  Returns localpart,domain on success; raises BadEmail
       on failure.
    """
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
    """Given the contents of a from line, and a map of supported email
       domains (in lowercase), raise BadEmail or return a normalized
       email address.
    """
    addr = addr.lower()
    localpart, domain = extractAddrSpec(addr)
    if domainmap is not None:
        domain = domainmap.get(domain, None)
        if domain is None:
            raise UnsupportedDomain("Domain not supported", addr)

    #XXXX Do these rules also hold for Yahoo?

    # addr+foo@ is an alias for addr@
    idx = localpart.find('+')
    if idx >= 0:
        localpart = localpart[:idx]
    # j.doe@ is the same as jdoe@.
    localpart = localpart.replace(".", "")
    
    return "%s@%s"%(localpart, domain)

class EmailBasedDistributor(bridgedb.Bridges.BridgeHolder):
    """Object that hands out bridges based on the email address of an incoming
       request and the current time period.
    """
    ## Fields:
    ##   emailHmac -- an hmac function used to order email addresses within
    ##       a ring.
    ##   ring -- a BridgeRing object to hold all the bridges we hand out.
    ##   store -- a database object to remember what we've given to whom.
    ##   domainmap -- a map from lowercase domains that we support mail from
    ##       to their canonical forms.
    def __init__(self, key, store, domainmap):
        key1 = bridgedb.Bridges.get_hmac(key, "Map-Addresses-To-Ring")
        self.emailHmac = bridgedb.Bridges.get_hmac_fn(key1, hex=False)

        key2 = bridgedb.Bridges.get_hmac(key, "Order-Bridges-In-Ring")
        self.ring = bridgedb.Bridges.BridgeRing(key2)
        self.ring.name = "email ring"
        # XXXX clear the store when the period rolls over!
        self.store = store
        self.domainmap = domainmap

    def insert(self, bridge):
        """Assign a bridge to this distributor."""
        self.ring.insert(bridge)

    def getBridgesForEmail(self, emailaddress, epoch, N=1):
        """Return a list of bridges to give to a user.
           emailaddress -- the user's email address, as given in a from line.
           epoch -- the time period when we got this request.  This can
               be any string, so long as it changes with every period.
           N -- the number of bridges to try to give back.
        """
        emailaddress = normalizeEmail(emailaddress, self.domainmap)
        if emailaddress is None:
            return [] #XXXX raise an exception.
        if self.store.has_key(emailaddress):
            result = []
            ids_str = self.store[emailaddress]
            logging.info("We've seen %r before. Sending the same bridges"
                         " as last time", emailaddress)
            for ident in bridgedb.Bridges.chopString(ids_str,
                                                     bridgedb.Bridges.ID_LEN):
                b = self.ring.getBridgeByID(ident)
                if b != None:
                    result.append(b)
            return result

        pos = self.emailHmac("<%s>%s" % (epoch, emailaddress))
        result = self.ring.getBridges(pos, N)
        memo = "".join(b.getID() for b in result)
        self.store[emailaddress] = memo
        return result
