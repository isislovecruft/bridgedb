# BridgeDB by Nick Mathewson.
# Copyright (c) 2007-2009, The Tor Project, Inc.
# See LICENSE for licensing information

"""
This module has functions to decide which bridges to hand out to whom.
"""

import bridgedb.Bridges
import bridgedb.Storage
import bridgedb.Util as Util

import re
import time
from ipaddr import IPv6Address, IPAddress

from bridgedb.Filters import filterAssignBridgesToRing
from bridgedb.Filters import filterBridgesByRules
from bridgedb.Filters import filterBridgesByIP4
from bridgedb.Filters import filterBridgesByIP6

import bridgedb.log as logging


def uniformMap(ip):
    """Map an IP to an arbitrary 'area' string, such that any two /24 addresses
       get the same string.

    >>> uniformMap('1.2.3.4')
    '1.2.3'
    """
    if type(IPAddress(ip)) is IPv6Address:
        return ":".join(IPv6Address(ip).exploded.split(':')[:4])
    else:
        return ".".join( ip.split(".")[:3] )

def getNumBridgesPerAnswer(ring, max_bridges_per_answer=3):
    if len(ring) < 20: n_bridges_per_answer = 1
    if 20 <= len(ring) < 100: n_bridges_per_answer = min(2, max_bridges_per_answer)
    if len(ring) >= 100: n_bridges_per_answer = max_bridges_per_answer

    logging.debug("Returning %d bridges from ring of len: %d"
                  % (n_bridges_per_answer, len(ring)))
    return n_bridges_per_answer

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
    def __init__(self, areaMapper, nClusters, key, ipCategories=(), answerParameters=None):
        self.areaMapper = areaMapper
        self.nClusters = nClusters
        self.answerParameters = answerParameters

        self.rings = []

        self.categories = [] #DOCDOC 
        for c in ipCategories:
            self.categories.append(c)

        key2 = bridgedb.Bridges.get_hmac(key, "Assign-Bridges-To-Rings")
        key3 = bridgedb.Bridges.get_hmac(key, "Order-Areas-In-Rings")
        self.areaOrderHmac = bridgedb.Bridges.get_hmac_fn(key3, hex=False)
        key4 = bridgedb.Bridges.get_hmac(key, "Assign-Areas-To-Rings")
        self.areaClusterHmac = bridgedb.Bridges.get_hmac_fn(key4, hex=True)

        # add splitter and cache the default rings
        # plus leave room for dynamic filters
        ring_cache_size  = self.nClusters + len(ipCategories) + 5
        self.splitter = bridgedb.Bridges.FilteredBridgeSplitter(key2,
                                               max_cached_rings=ring_cache_size)

        logging.debug("added splitter %s" % self.splitter)

    def prepopulateRings(self):
        # populate all rings (for dumping assignments and testing)
        for filterFn in [None, filterBridgesByIP4, filterBridgesByIP6]:
            n = self.nClusters
            for category in self.categories:
                g = filterAssignBridgesToRing(self.splitter.hmac,
                        self.nClusters +
                        len(self.categories),
                        n)
                bridgeFilterRules = [g]
                if filterFn:
                    bridgeFilterRules.append(filterFn)
                ruleset = frozenset(bridgeFilterRules)
                key1 = bridgedb.Bridges.get_hmac(self.splitter.key,
                        "Order-Bridges-In-Ring-%d"%n) 
                n += 1
                ring = bridgedb.Bridges.BridgeRing(key1, self.answerParameters)
                self.splitter.addRing(ring, ruleset, filterBridgesByRules(bridgeFilterRules),
                                      populate_from=self.splitter.bridges)


            # populate all ip clusters
            for clusterNum in xrange(self.nClusters):
                g = filterAssignBridgesToRing(self.splitter.hmac,
                                              self.nClusters +
                                              len(self.categories),
                                              clusterNum) 
                bridgeFilterRules = [g]
                if filterFn:
                    bridgeFilterRules.append(filterFn)
                ruleset = frozenset(bridgeFilterRules)
                key1 = bridgedb.Bridges.get_hmac(self.splitter.key,
                                                 "Order-Bridges-In-Ring-%d"%clusterNum) 
                ring = bridgedb.Bridges.BridgeRing(key1, self.answerParameters)
                self.splitter.addRing(ring, ruleset, filterBridgesByRules(bridgeFilterRules),
                                      populate_from=self.splitter.bridges)

    def clear(self):
        self.splitter.clear()

    def insert(self, bridge):
        """Assign a bridge to this distributor."""
        self.splitter.insert(bridge)

    def getBridgesForIP(self, ip, epoch, N=1, countryCode=None,
                        bridgeFilterRules=None):
        """Return a list of bridges to give to a user.
           ip -- the user's IP address, as a dotted quad.
           epoch -- the time period when we got this request.  This can
               be any string, so long as it changes with every period.
           N -- the number of bridges to try to give back.
        """
        if not bridgeFilterRules: bridgeFilterRules=[]
        logging.debug("getBridgesForIP(%s, %s, %s, %s"
                      % (Util.logSafely(ip), epoch, N, bridgeFilterRules))
        if not len(self.splitter):
            logging.debug("bailing without splitter")
            return []

        area = self.areaMapper(ip)

        logging.info("area is %s" % Util.logSafely(area))
        
        key1 = ''
        pos = 0
        n = self.nClusters

        # only one of ip categories or area clustering is active
        # try to match the request to an ip category
        for category in self.categories:
            # IP Categories
            if category.contains(ip):
                g = filterAssignBridgesToRing(self.splitter.hmac,
                                                      self.nClusters +
                                                      len(self.categories),
                                                      n)
                bridgeFilterRules.append(g)
                logging.info("category<%s>%s" % (epoch, Util.logSafely(area)))
                pos = self.areaOrderHmac("category<%s>%s" % (epoch, area))
                key1 = bridgedb.Bridges.get_hmac(self.splitter.key,
                                             "Order-Bridges-In-Ring-%d"%n) 
                break;
            n += 1

        # if no category matches, use area clustering
        else:
            # IP clustering
            h = int( self.areaClusterHmac(area)[:8], 16)
            # length of numClusters
            clusterNum = h % self.nClusters
 
            g = filterAssignBridgesToRing(self.splitter.hmac,
                                          self.nClusters +
                                          len(self.categories),
                                          clusterNum) 
            bridgeFilterRules.append(g)
            pos = self.areaOrderHmac("<%s>%s" % (epoch, area))
            key1 = bridgedb.Bridges.get_hmac(self.splitter.key,
                                             "Order-Bridges-In-Ring-%d"%clusterNum) 

        logging.debug("bridgeFilterRules: %s" % bridgeFilterRules)

        # try to find a cached copy
        ruleset = frozenset(bridgeFilterRules)

        # See if we have a cached copy of the ring,
        # otherwise, add a new ring and populate it
        if ruleset in self.splitter.filterRings.keys():
            logging.debug("Cache hit %s" % ruleset)
            _,ring = self.splitter.filterRings[ruleset]

        # else create the ring and populate it
        else:
            logging.debug("Cache miss %s" % ruleset)
            ring = bridgedb.Bridges.BridgeRing(key1, self.answerParameters)
            self.splitter.addRing(ring, ruleset, filterBridgesByRules(bridgeFilterRules),
                                  populate_from=self.splitter.bridges)

        # get an appropriate number of bridges
        return ring.getBridges(pos, getNumBridgesPerAnswer(ring, max_bridges_per_answer=N))

    def __len__(self):
        return len(self.splitter)

    def dumpAssignments(self, f, description=""):
        self.splitter.dumpAssignments(f, description)


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

MAX_EMAIL_RATE = 3*3600

class BadEmail(Exception):
    """Exception raised when we get a bad email address."""
    def __init__(self, msg, email):
        Exception.__init__(self, msg)
        self.email = email

class UnsupportedDomain(BadEmail):
    """Exception raised when we get an email address from a domain we
       don't know."""
    pass

class TooSoonEmail(BadEmail):
    """Raised when we got a request from this address too recently."""
    pass

class IgnoreEmail(BadEmail):
    """Raised when we get requests from this address after rate warning."""
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

def normalizeEmail(addr, domainmap, domainrules):
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
    rules = domainrules.get(domain, [])
    if 'ignore_dots' in rules:
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
    def __init__(self, key, domainmap, domainrules,
                 answerParameters=None):
        key1 = bridgedb.Bridges.get_hmac(key, "Map-Addresses-To-Ring")
        self.emailHmac = bridgedb.Bridges.get_hmac_fn(key1, hex=False)

        key2 = bridgedb.Bridges.get_hmac(key, "Order-Bridges-In-Ring")
        # XXXX clear the store when the period rolls over!
        self.domainmap = domainmap
        self.domainrules = domainrules
        self.answerParameters = answerParameters

        #XXX cache options not implemented
        self.splitter = bridgedb.Bridges.FilteredBridgeSplitter(key2,
                                                            max_cached_rings=5)

    def clear(self):
        self.splitter.clear()
        #self.ring.clear() # should be take care of by above

    def insert(self, bridge):
        """Assign a bridge to this distributor."""
        self.splitter.insert(bridge)

    def getBridgesForEmail(self, emailaddress, epoch, N=1,
            parameters=None, countryCode=None, bridgeFilterRules=None):
        """Return a list of bridges to give to a user.
           emailaddress -- the user's email address, as given in a from line.
           epoch -- the time period when we got this request.  This can
               be any string, so long as it changes with every period.
           N -- the number of bridges to try to give back.
        """
        if not bridgeFilterRules:
            bridgeFilterRules=[]
        now = time.time()
        try:
            emailaddress = normalizeEmail(emailaddress, self.domainmap,
                                          self.domainrules)
        except BadEmail:
            return [] #XXXX log the exception
        if emailaddress is None:
            return [] #XXXX raise an exception.

        db = bridgedb.Storage.getDB()
        wasWarned = db.getWarnedEmail(emailaddress)

        lastSaw = db.getEmailTime(emailaddress)
        safe = Util.logSafely(emailaddress)

        if lastSaw is not None and lastSaw + MAX_EMAIL_RATE >= now:
            if wasWarned:
                msg  = "Got a request for bridges from %r; we already" % safe
                msg += " sent a warning. Ignoring." % safe
                logging.info(msg)
                raise IgnoreEmail("Client was warned" % Util.logSafely(emailaddress))
            else:
                db.setWarnedEmail(emailaddress, True, now)
                db.commit() 

            msg  = "Got a request for bridges from %r; we already" % safe
            msg += " answered in the last %d seconds. Warning." % MAX_EMAIL_RATE
            logging.info(msg)
            raise TooSoonEmail("Too many emails; wait till later", emailaddress)

        # warning period is over
        elif wasWarned:
            db.setWarnedEmail(emailaddress, False) 

        pos = self.emailHmac("<%s>%s" % (epoch, emailaddress))

        ring = None
        ruleset = frozenset(bridgeFilterRules)
        if ruleset in self.splitter.filterRings.keys():
            logging.debug("Cache hit %s" % ruleset)
            _,ring = self.splitter.filterRings[ruleset]
        else:
            # cache miss, add new ring
            logging.debug("Cache miss %s" % ruleset)

            # add new ring 
            key1 = bridgedb.Bridges.get_hmac(self.splitter.key,
                    "Order-Bridges-In-Ring")
            ring = bridgedb.Bridges.BridgeRing(key1, self.answerParameters)
            # debug log: cache miss 
            self.splitter.addRing(ring, ruleset,
                                  filterBridgesByRules(bridgeFilterRules),
                                  populate_from=self.splitter.bridges)

        result = ring.getBridges(pos, getNumBridgesPerAnswer(ring, max_bridges_per_answer=N))

        db.setEmailTime(emailaddress, now)
        db.commit()
        return result

    def __len__(self):
        return len(self.splitter)

    def cleanDatabase(self):
        db = bridgedb.Storage.getDB()
        try:
            db.cleanEmailedBridges(time.time()-MAX_EMAIL_RATE)
            db.cleanWarnedEmails(time.time()-MAX_EMAIL_RATE)
        except:
            db.rollback()
            raise
        else:
            db.commit()

    def dumpAssignments(self, f, description=""):
        self.splitter.dumpAssignments(f, description)

    def prepopulateRings(self):
        # populate all rings (for dumping assignments and testing)
        for filterFn in [filterBridgesByIP4, filterBridgesByIP6]:
            ruleset = frozenset([filterFn])
            key1 = bridgedb.Bridges.get_hmac(self.splitter.key,
                    "Order-Bridges-In-Ring")
            ring = bridgedb.Bridges.BridgeRing(key1, self.answerParameters)
            self.splitter.addRing(ring, ruleset,
                                  filterBridgesByRules([filterFn]),
                                  populate_from=self.splitter.bridges)
