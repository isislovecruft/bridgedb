# BridgeDB by Nick Mathewson.
# Copyright (c) 2007-2009, The Tor Project, Inc.
# See LICENSE for licensing information

"""
This module has functions to decide which bridges to hand out to whom.
"""

import bridgedb.Bridges
import bridgedb.Storage

import logging
import re
import time

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
    def __init__(self, areaMapper, nClusters, key, ipCategories=(),
                 answerParameters=None):
        self.areaMapper = areaMapper

        self.rings = []
        self.categoryRings = [] #DOCDDOC
        self.categories = [] #DOCDOC
        for n in xrange(nClusters):
            key1 = bridgedb.Bridges.get_hmac(key, "Order-Bridges-In-Ring-%d"%n)
            self.rings.append( bridgedb.Bridges.BridgeRing(key1,
                                                           answerParameters) )
            self.rings[-1].setName("IP ring %s"%len(self.rings))
        n = nClusters
        for c in ipCategories:
            logging.info("Building ring: Order-Bridges-In-Ring-%d"%n)
            key1 = bridgedb.Bridges.get_hmac(key, "Order-Bridges-In-Ring-%d"%n)
            ring = bridgedb.Bridges.BridgeRing(key1, answerParameters)
            self.categoryRings.append( ring )
            self.categoryRings[-1].setName(
                "IP category ring %s"%len(self.categoryRings))
            self.categories.append( (c, ring) )
            n += 1

        key2 = bridgedb.Bridges.get_hmac(key, "Assign-Bridges-To-Rings")
        self.splitter = bridgedb.Bridges.FixedBridgeSplitter(key2,
                                       self.rings+self.categoryRings)

        key3 = bridgedb.Bridges.get_hmac(key, "Order-Areas-In-Rings")
        self.areaOrderHmac = bridgedb.Bridges.get_hmac_fn(key3, hex=False)

        key4 = bridgedb.Bridges.get_hmac(key, "Assign-Areas-To-Rings")
        self.areaClusterHmac = bridgedb.Bridges.get_hmac_fn(key4, hex=True)

    def clear(self):
        self.splitter.clear()

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

        logging.info("area is %s" % area)

        for category, ring in self.categories:
            logging.info("---------------------------------")
            if category.contains(ip):
                logging.info("category<%s>%s"%(epoch,area))
                pos = self.areaOrderHmac("category<%s>%s"%(epoch,area))
                return ring.getBridges(pos, N)

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

    def __len__(self):
        return sum(len(r) for r in self.rings)

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
        self.ring = bridgedb.Bridges.BridgeRing(key2, answerParameters)
        self.ring.name = "email ring"
        # XXXX clear the store when the period rolls over!
        self.domainmap = domainmap
        self.domainrules = domainrules

    def clear(self):
        self.ring.clear()

    def insert(self, bridge):
        """Assign a bridge to this distributor."""
        self.ring.insert(bridge)

    def getBridgesForEmail(self, emailaddress, epoch, N=1, parameters=None):
        """Return a list of bridges to give to a user.
           emailaddress -- the user's email address, as given in a from line.
           epoch -- the time period when we got this request.  This can
               be any string, so long as it changes with every period.
           N -- the number of bridges to try to give back.
        """
        now = time.time()
        try:
          emailaddress = normalizeEmail(emailaddress, self.domainmap,
                                      self.domainrules)
        except BadEmail:
          return [] #XXXX log the exception
        if emailaddress is None:
            return [] #XXXX raise an exception.

        db = bridgedb.Storage.getDB()

        lastSaw = db.getEmailTime(emailaddress)
        if lastSaw is not None and lastSaw + MAX_EMAIL_RATE >= now:
            logging.warn("Got a request for bridges from %r; we already "
                         "answered one within the last %d seconds. Ignoring.",
                         emailaddress, MAX_EMAIL_RATE)
            raise TooSoonEmail("Too many emails; wait till later", emailaddress)

        pos = self.emailHmac("<%s>%s" % (epoch, emailaddress))
        result = self.ring.getBridges(pos, N)

        db.setEmailTime(emailaddress, now)
        db.commit()
        return result

    def __len__(self):
        return len(self.ring)

    def cleanDatabase(self):
        db = bridgedb.Storage.getDB()
        try:
            db.cleanEmailedBridges(time.time()-MAX_EMAIL_RATE)
        except:
            db.rollback()
            raise
        else:
            db.commit()


class FileDistributorBean:
    """A file distributor bean
    """
    def __init__(self, name, needed):
        self.name = name
        if needed == "*":
            # Set to rediculously high number
            needed = 1000000
        self.needed = int(needed)
        self.allocated = 0

class FileDistributor:
    """FileDistributor reads a number of file distributors from the config.
       They're expected to be in the following format:

       FILE_DISTRIBUTORS = { "name1": 10, "name2": 15, "foobar": 3 }

       This syntax means that certain distributors ("name1", "name2" and so on)
       are given a number of bridges (10, 15 and so on). Names can be anything.
       The name will later be the prefix of the file that is written with the
       assigned number of bridges in it. Instead of a number, a wildcard item
       ("*") is allowed, too. This means that that file distributor will get
       maximum bridges (as many as are left in the unallocated bucket).

       The files will be written in ip:port format, one bridge per line.

       The way this works internally is as follows:

       First of all, the assignBridgesToDistributors() routine runs through
       the database of bridges and looks up the 'distributor' field of each 
       bridge. Unallocated bridges are sent to a pool for later assignement.
       Already allocated bridges for file distributors are sorted and checked.
       They're checked for whether the distributor still exists in the current
       config and also whether the number of assigned bridges is still valid.
       If either the distributor is not existing anymore or too many bridges
       are currently assigned to her, bridges will go to the unassigned pool.

       In the second step, after bridges are sorted and the unassigned pool is
       ready, the assignBridgesToDistributors() routine assigns one bridge
       from the unassigned pool to a known distributor at a time until it
       either runs out of bridges in the unallocated pool or the number of
       needed bridges for that distributor is fullfilled.

       When all bridges are assigned in this way, they then can then be dumped
       into files by calling the dumpBridges() routine.
    """

    def __init__(self, cfg):
        self.cfg = cfg
        self.distributorList = []
        self.unallocatedList = []
        self.unallocated_available = False
        self.db = bridgedb.Storage.Database(self.cfg.DB_FILE+".sqlite",
                                            self.cfg.DB_FILE)

    def __del__(self):
        self.db.close()

    def addToUnallocatedList(self, id):
        """Add a bridge by database id into the unallocated pool
        """
        try:
            self.db.updateDistributorForId("unallocated", id)
        except:
            self.db.rollback()
            raise
        else:
            self.db.commit()
        self.unallocatedList.append(id)
        self.unallocated_available = True

    def knownFileDistributor(self, distributor):
        """Do we know this distributor?
        """
        for d in self.distributorList:
            if d.name == distributor:
                return d
        return None

    def assignUnallocatedBridge(self, distributor):
        """Assign an unallocated bridge to a certain distributor
        """
        distributor.allocated += 1
        id = self.unallocatedList.pop()
        #print "ID: %d NAME: %s" % (id, distributor.name)
        try:
            self.db.updateDistributorForId(distributor.name, id)
        except:
            self.db.rollback()
            raise
        else:
            self.db.commit()
        if len(self.unallocatedList) < 1:
            self.unallocated_available = False
        return True

    def assignBridgesToDistributors(self):
        """Read file distributors from the configuration, sort them and write
           necessary changes to the database
        """
        # Build distributor list
        for k, v in self.cfg.FILE_DISTRIBUTORS.items():
            d = FileDistributorBean(k, v)
            self.distributorList.append(d)

        # Loop through all bridges and sort out our distributors
        allBridges = self.db.getAllBridges()
        for bridge in allBridges:
            distributor =  bridge[4]
            if distributor == "unallocated":
                self.addToUnallocatedList(bridge[0])
                continue

            # Check if we know this distributor
            d = self.knownFileDistributor(distributor)
            if d is not None:
                # Does this distributor need another one?
                # We assume that d.allocated is 0 in the beginning
                if d.allocated < d.needed:
                    d.allocated += 1
                else:
                    self.addToUnallocatedList(bridge[0])
            # We don't know it. Maybe an old entry. Free it.
            else:
                # DON'T free https or email allocations!
                if distributor != "https" and distributor != "email":
                    self.addToUnallocatedList(bridge[0])

        # Loop though distributorList while we have and need unallocated 
        # bridges, assign one bridge at a time
        while self.unallocated_available and len(self.distributorList) > 0:
            for d in self.distributorList:
                if d.allocated < d.needed:
                    if not self.assignUnallocatedBridge(d):
                        print "Couldn't assign unallocated bridge to %s" % d.name
                else:
                    # When we have enough bridges, remove from list
                    self.distributorList.remove(d)
         

    def dumpBridges(self):
        """Dump all known file distributors to files
        """
        # Dump https, email and unreserved, too
        self.cfg.FILE_DISTRIBUTORS["https"] = 0
        self.cfg.FILE_DISTRIBUTORS["email"] = 0
        self.cfg.FILE_DISTRIBUTORS["unallocated"] = 0
        # Loop through all distributors and dump their bridges to files
        for distributor, _ in self.cfg.FILE_DISTRIBUTORS.items():
            fileName = distributor + "-" + time.strftime("%Y-%m-%d") + ".brdgs"
            f = open(fileName, 'w')
            f.write("Here are your bridges, %s:\n" % distributor)
            bForDistributor = self.db.getBridgesForDistributor(distributor) 
            print "Dumping %d bridges for %s to %s" % (len(bForDistributor), distributor, fileName)
            for bridge in bForDistributor:
                line = "%s:%s" % (bridge[2], bridge[3])
                f.write(line + '\n')
            f.close
