# See LICENSE for licensing information

"""
This module has low-level functionality for parsing bridges and arranging
them in rings.
"""

import binascii
import bisect
import hmac
import logging
import re
import sha
import socket
import time
import ipaddr
import random

import bridgedb.Storage
import bridgedb.Bucket

HEX_FP_LEN = 40
ID_LEN = 20

DIGESTMOD = sha
HEX_DIGEST_LEN = 40
DIGEST_LEN = 20

def is_valid_ip(ip):
    """Return True if ip is the string encoding of a valid IPv4 address,
       and False otherwise.

    >>> is_valid_ip('1.2.3.4')
    True
    >>> is_valid_ip('1.2.3.255')
    True
    >>> is_valid_ip('1.2.3.256')
    False
    >>> is_valid_ip('1')
    False
    >>> is_valid_ip('1.2.3')
    False
    >>> is_valid_ip('xyzzy')
    False
    """

    # ipaddr does not treat "1.2" as a synonym for "0.0.1.2"
    try:
        ipaddr.IPAddress(ip)
    except ValueError:
        # not a valid IPv4 or IPv6 address
        return False
    return True

def is_valid_fingerprint(fp):
    """Return true iff fp in the right format to be a hex fingerprint
       of a Tor server.
    """
    if len(fp) != HEX_FP_LEN:
        return False
    try:
        fromHex(fp)
    except TypeError:
        return False
    else:
        return True

def is_valid_or_address(or_address):
    """Return true iff or_address is in the right format
       (ip,frozenset(port)) or (ip, frozenset(port_low,port_high)) for ranges
    """
    if len(or_address) != 2: return False
    ip,port = or_address
    if not is_valid_ip(ip): return False
    if type(port) is not int: return False
    if not (1 <= port <= 65535): return False
    return True

toHex = binascii.b2a_hex
fromHex = binascii.a2b_hex

def get_hmac(k,v):
    """Return the hmac of v using the key k."""
    h = hmac.new(k, v, digestmod=DIGESTMOD)
    return h.digest()

def get_hmac_fn(k, hex=True):
    """Return a function that computes the hmac of its input using the key k.
       If 'hex' is true, the output of the function will be hex-encoded."""
    h = hmac.new(k, digestmod=DIGESTMOD)
    def hmac_fn(v):
        h_tmp = h.copy()
        h_tmp.update(v)
        if hex:
            return h_tmp.hexdigest()
        else:
            return h_tmp.digest()
    return hmac_fn

def chopString(s, size):
    """Generator. Given a string and a length, divide the string into pieces
       of no more than that length.
    """
    for pos in xrange(0, len(s), size):
        yield s[pos:pos+size]

class Bridge:
    """Holds information for a single bridge"""
    ## Fields:
    ##   nickname -- The bridge's nickname.  Not currently used.
    ##   ip -- The bridge's IP address, as a dotted quad.
    ##   orport -- The bridge's OR port.
    ##   fingerprint -- The bridge's identity digest, in lowercase hex, with
    ##       no spaces.
    ##   running,stable -- DOCDOC
    ##   blockingCountries -- list of country codes blocking this bridge
    def __init__(self, nickname, ip, orport, fingerprint=None, id_digest=None,
                 or_addresses=None):
        """Create a new Bridge.  One of fingerprint and id_digest must be
           set."""
        self.nickname = nickname
        self.ip = ip
        self.orport = orport
        if not or_addresses: or_addresses = {}
        self.or_addresses = or_addresses
        self.running = self.stable = None
        self.blockingCountries = None
        if id_digest is not None:
            assert fingerprint is None
            if len(id_digest) != DIGEST_LEN:
                raise TypeError("Bridge with invalid ID")
            self.fingerprint = toHex(id_digest)
        elif fingerprint is not None:
            if not is_valid_fingerprint(fingerprint):
                raise TypeError("Bridge with invalid fingerprint (%r)"%
                                fingerprint)
            self.fingerprint = fingerprint.lower()
        else:
            raise TypeError("Bridge with no ID")

    def getID(self):
        """Return the bridge's identity digest."""
        return fromHex(self.fingerprint)

    def __repr__(self):
        """Return a piece of python that evaluates to this bridge."""
        if self.or_addresses:
            return "Bridge(%r,%r,%d,%r,or_addresses=%s)"%(
                self.nickname, self.ip, self.orport, self.fingerprint,
                self.or_addresses)
        return "Bridge(%r,%r,%d,%r)"%(
            self.nickname, self.ip, self.orport, self.fingerprint)

    def getConfigLine(self,includeFingerprint=False,
            selectFromORAddresses=False,
            needIPv4=True, needIPv6=False):
        """Return a line describing this bridge for inclusion in a torrc."""

        # select an address:port from or-addresses
        if selectFromORAddresses and self.or_addresses:
            filtered_addresses = None
            # bridges may have both classes. we only return one.
            if needIPv4:
                f = lambda x: type(x[0]) is ipaddr.IPv4Address
                filtered_addresses = filter(f, self.or_addresses.items())
            elif needIPv6:
                f = lambda x: type(x[0]) is ipaddr.IPv6Address
                filtered_addresses = filter(f, self.or_addresses.items())

            #XXX: we could instead have two lists of or-addresses
            if filtered_addresses:
                address,portlist = random.choice(filtered_addresses)
                if type(address) is ipaddr.IPv6Address:
                    ip = "[%s]"%address
                else:
                    ip = "%s"%address
                orport = portlist.getPort() #magic

        # default to ip,orport ; ex. when logging
        else:
            ip = self.ip
            orport = self.orport

        if includeFingerprint:
            return "bridge %s:%d %s" % (ip, orport, self.fingerprint)
        else:
            return "bridge %s:%d" % (ip, orport)  

    def getAllConfigLines(self,includeFingerprint=False):
        """Generator. Iterate over all valid config lines for this bridge."""
        # warning: a bridge with large port ranges may generate thousands
        # of lines of output
        for address,portlist in self.or_addresses.items():
            if type(address) is ipaddr.IPv6Address:
                ip = "[%s]" % address
            else:
                ip = "%s" % address

            for orport in portlist:
                if includeFingerprint:
                    yield "bridge %s:%d %s" % (ip,orport,self.fingerprint)
                else:
                    yield "bridge %s:%d" % (ip,orport)

    def assertOK(self):
        assert is_valid_ip(self.ip)
        assert is_valid_fingerprint(self.fingerprint)
        assert 1 <= self.orport <= 65535

    def setStatus(self, running=None, stable=None):
        if running is not None:
            self.running = running
        if stable is not None:
            self.stable = stable

    def setBlockingCountries(self, blockingCountries):
        if blockingCountries is not None:
            self.blockingCountries = blockingCountries

    def isBlocked(self, countryCode):
        if self.blockingCountries is not None and countryCode is not None:
            if countryCode in self.blockingCountries:
                return True
        return False 

def parseDescFile(f, bridge_purpose='bridge'):
    """Generator. Parses a cached-descriptors file 'f' and yeilds a Bridge object
       for every entry whose purpose matches bridge_purpose.
       This Generator understands the new descriptor format described in 
       186-multiple-orports.txt

       The new specification provides for specifying multiple ORports as well
       as supporting new address format for IPv6 addresses.

       The router descriptor "or-address" may occur zero, one, or multiple times.
       parseDescFile adds each ADDRESS:PORTSPEC to the Bridge.or_addresses list.

       The "or-address" should not duplicate the address:port pair from the "router"
       description. (Should we try to catch this case?)

       A node may not list more than 8 or-address lines.
         (should we try to enforce this too?)

       Here is the new format:

       or-address SP ADDRESS ":" PORTLIST NL
       ADDRESS = IP6ADDR | IP4ADDR
       IPV6ADDR = an ipv6 address, surrounded by square brackets.
       IPV4ADDR = an ipv4 address, represented as a dotted quad.
       PORTLIST = PORTSPEC | PORTSPEC "," PORTLIST
       PORTSPEC = PORT | PORT "-" PORT
       PORT = a number between 1 and 65535 inclusive.
    """
   
    nickname = ip = orport = fingerprint = purpose = None
    num_or_address_lines = 0
    or_addresses = {}

    for line in f:
        line = line.strip()
        if line.startswith("opt "):
            line = line[4:]

        if line.startswith("@purpose "):
            items = line.split()
            purpose = items[1]
        elif line.startswith("router "):
            items = line.split()
            if len(items) >= 4:
                nickname = items[1]
                ip = items[2]
                orport = int(items[3])
        elif line.startswith("fingerprint "):
            fingerprint = line[12:].replace(" ", "")
        elif line.startswith("or-address "):
            if num_or_address_lines < 8:
                line = line[11:]
                address,portlist = parseORAddressLine(line)
                try:
                    or_addresses[address].add(portlist)
                except KeyError:
                    or_addresses[address] = portlist
            else:
                logging.warn("Skipping extra or-address line "\
                             "from Bridge with ID %r" % id)
            num_or_address_lines += 1
        elif line.startswith("router-signature"):
            purposeMatches = (purpose == bridge_purpose or
                              bridge_purpose is None)
            if purposeMatches and nickname and ip and orport and fingerprint:
                b = Bridge(nickname, ip, orport, fingerprint,
                           or_addresses=or_addresses)
                b.assertOK()
                yield b
            nickname = ip = orport = fingerprint = purpose = None 
            num_or_address_lines = 0
            or_addresses = {}

class PortList:
    """ container class for port ranges
    """

    def __init__(self, *args, **kwargs):
        self.ports = set()
        self.ranges = [] 
        self.portdispenser = None
        if len(args) == 1:
            if type(args[0]) is str:
                ports = [p.split('-') for p in args[0].split(',')]
                # truncate per spec
                ports = ports[:16]
                for ps in ports:
                    try: ps = [int(x) for x in ps]
                    except ValueError: break
                    if len(ps) == 1: self.add(ps[0])
                    elif len(ps) == 2: self.add(ps[0],ps[1])
            else:
                self.add(args[0])
        elif len(args) == 2:
            l,h = args
            self.add(l,h)

    def _sanitycheck(self, val):
        #XXX: if debug=False this is disabled. bad!
        assert type(val) is int
        assert(val > 0)
        assert(val <= 65535) 

    def __contains__(self, val1, val2=None):
        self._sanitycheck(val1)
        if val2: self.sanitycheck(val2)

        # check a single port
        if not val2 and val1:
            if val1 in self.ports: return True
            for start,end in self.ranges:
                f = lambda x: start <= x <= end
                if f(val1): return True
            return False

        if val2 and val1:
            for start,end in self.ranges:
                f = lambda x: start <= x <= end
                if f(val1) and f(val2): return True

        for start,end in self.ranges:
            f = lambda x: start <= x <= end
            if f(val): return True

    def add(self, val1, val2=None):
        self._sanitycheck(val1)

        # add as a single port instead
        if val2 == val1: val2 = None
        if val2:
            self._sanitycheck(val2)
            start = min(val1,val2)
            end = max(val1,val2)
            self.ranges.append((start,end))
            # reduce to largest continuous ranges
            self._squash()
        else:
            if val1 in self: return
            self.ports.add(val1)

        # reset port dispenser
        if self.portdispenser:
            self.portdispenser = None

    def getPort(self):
        # returns a single valid port
        if not self.portdispenser:
            self.portdispenser = self.__iter__()
        try:
            return self.portdispenser.next()
        except StopIteration, AttributeError:
            self.portdispenser = self.__iter__()
            return self.portdispenser.next()

    def _squash(self):
        # merge intersecting ranges
        if len(self.ranges) > 1:
            self.ranges.sort(key=lambda x: x[0])
            squashed = [self.ranges.pop(0)]
            for r in self.ranges:
                if (squashed[-1][0] <= r[0] <= squashed[-1][1]):
                    #intersection, extend r1, drop r2
                    if r[1] > squashed[-1][1]: 
                        squashed[-1] = (squashed[-1][0],r[1])
                    # drop r
                else:
                    # keep r
                    squashed.append(r)

            self.ranges = squashed

        # drop enclosed ports
        ports = self.ports.copy()
        for p in self.ports:
            for s,e in self.ranges:
                if s <= p <= e:
                    ports.remove(p)
        self.ports = ports

    def __iter__(self):
        for p in self.ports:
            yield p
        for l,h in self.ranges:
            # +1 for inclusive range
            for rr in xrange(l,h+1):
                yield rr

    def __str__(self):
        s = ""
        for p in self.ports:
            s += "".join(", %s"%p)
        for l,h in self.ranges:
            s += ", %s-%s" % (l,h)
        return s.lstrip(", ")

    def __repr__(self):
        return "PortList('%s')" % self.__str__()

def parseORAddressLine(line):
    #XXX should these go somewhere else?
    re_ipv6 = re.compile("\[([a-fA-F0-9:]+)\]:(.*$)")
    re_ipv4 = re.compile("((?:\d{1,3}\.?){4}):(.*$)")

    address = None
    portlist = None
    # try regexp to discover ip version
    for regex in [re_ipv4, re_ipv6]:
        m = regex.match(line)
        if m:
            try:
                address  = ipaddr.IPAddress(m.group(1))
                portstring = m.group(2)
            except IndexError, ValueError: break
            portlist = PortList(portstring)
    return address,portlist

def parseStatusFile(f):
    """DOCDOC"""
    ID = None
    for line in f:
        line = line.strip()
        if line.startswith("opt "):
            line = line[4:]

        if line.startswith("r "):
            try:
                ID = binascii.a2b_base64(line.split()[2]+"=")
            except binascii.Error:
                logging.warn("Unparseable base64 ID %r", line.split()[2])
        elif ID and line.startswith("s "):
            flags = line.split()
            yield ID, ("Running" in flags), ("Stable" in flags)

def parseCountryBlockFile(f):
    """Generator. Parses a blocked-bridges file 'f', and yields a
       fingerprint, countryCode tuple for every entry"""
    fingerprint = countryCode = None
    for line in f:
        line = line.strip()
        m = re.match(r"fingerprint\s+(?P<fingerprint>\w+?)\s+country-code\s+(?P<countryCode>\w+)$", line)
        try:
            fingerprint = m.group('fingerprint').lower()
            countryCode = m.group('countryCode').lower()
            yield fingerprint, countryCode
        except AttributeError, IndexError:
            logging.warn("Unparseable line in blocked-bridges file: %s", line) 

class BridgeHolder:
    """Abstract base class for all classes that hold bridges."""
    def insert(self, bridge):
        raise NotImplementedError

    def clear(self):
        pass

    def assignmentsArePersistent(self):
        return True

    def dumpAssignments(self, f, description=""):
        pass

class BridgeRingParameters:
    """DOCDOC"""
    def __init__(self, needPorts=(), needFlags=()):
        """DOCDOC takes list of port, count"""
        for port,count in needPorts:
            if not (1 <= port <= 65535):
                raise TypeError("Port %s out of range."%port)
            if count <= 0:
                raise TypeError("Count %s out of range."%count)
        for flag, count in needFlags:
            flag = flag.lower()
            if flag not in [ "stable" ]:
                raise TypeError("Unsupported flag %s"%flag)
            if count <= 0:
                raise TypeError("Count %s out of range."%count)

        self.needPorts = needPorts[:]
        self.needFlags = [(flag.lower(),count) for flag, count in needFlags[:] ]

class BridgeRing(BridgeHolder):
    """Arranges bridges in a ring based on an hmac function."""
    ## Fields:
    ##   bridges: a map from hmac value to Bridge.
    ##   bridgesByID: a map from bridge ID Digest to Bridge.
    ##   isSorted: true iff sortedKeys is currently sorted.
    ##   sortedKeys: a list of all the hmacs, in order.
    ##   name: a string to represent this ring in the logs.
    def __init__(self, key, answerParameters=None):
        """Create a new BridgeRing, using key as its hmac key."""
        self.bridges = {}
        self.bridgesByID = {}
        self.hmac = get_hmac_fn(key, hex=False)
        self.isSorted = False
        self.sortedKeys = []
        if answerParameters is None:
            answerParameters = BridgeRingParameters()
        self.answerParameters = answerParameters

        self.subrings = [] #DOCDOC
        for port,count in self.answerParameters.needPorts:
            #note that we really need to use the same key here, so that
            # the mapping is in the same order for all subrings.
            self.subrings.append( ('port',port,count,BridgeRing(key,None)) )
        for flag,count in self.answerParameters.needFlags:
            self.subrings.append( ('flag',flag,count,BridgeRing(key,None)) )

        self.setName("Ring")

    def setName(self, name):
        """DOCDOC"""
        self.name = name
        for tp,val,_,subring in self.subrings:
            if tp == 'port':
                subring.setName("%s (port-%s subring)"%(name, val))
            else:
                subring.setName("%s (%s subring)"%(name, val))

    def __len__(self):
        return len(self.bridges)

    def clear(self):
        self.bridges = {}
        self.bridgesByID = {}
        self.isSorted = False
        self.sortedKeys = []

        for tp, val, count, subring in self.subrings:
            subring.clear()

    def insert(self, bridge):
        """Add a bridge to the ring.  If the bridge is already there,
           replace the old one."""
        for tp,val,_,subring in self.subrings:
            if tp == 'port':
                if val == bridge.orport:
                    subring.insert(bridge)
            else:
                assert tp == 'flag' and val == 'stable'
                if val == 'stable' and bridge.stable:
                    subring.insert(bridge)

        ident = bridge.getID()
        pos = self.hmac(ident)
        if not self.bridges.has_key(pos):
            self.sortedKeys.append(pos)
            self.isSorted = False
        self.bridges[pos] = bridge
        self.bridgesByID[ident] = bridge
        logging.debug("Adding %s to %s", bridge.getConfigLine(True), self.name)

    def _sort(self):
        """Helper: put the keys in sorted order."""
        if not self.isSorted:
            self.sortedKeys.sort()
            self.isSorted = True

    def _getBridgeKeysAt(self, pos, N=1):
        """Helper: return the N keys appearing in the ring after position
           pos"""
        assert len(pos) == DIGEST_LEN
        if N >= len(self.sortedKeys):
            return self.sortedKeys
        if not self.isSorted:
            self._sort()
        idx = bisect.bisect_left(self.sortedKeys, pos)
        r = self.sortedKeys[idx:idx+N]
        if len(r) < N:
            # wrap around as needed.
            r.extend(self.sortedKeys[:N - len(r)])
        assert len(r) == N
        return r

    def getBridges(self, pos, N=1, countryCode=None):
        """Return the N bridges appearing in the ring after position pos"""
        forced = []
        for _,_,count,subring in self.subrings:
            if len(subring) < count:
                count = len(subring)
            forced.extend(subring._getBridgeKeysAt(pos, count))

        keys = [ ]
        for k in forced + self._getBridgeKeysAt(pos, N):
            if k not in keys:
                keys.append(k)
        keys = keys[:N]
        keys.sort()

        #Do not return bridges from the same /16
        bridges = [ self.bridges[k] for k in keys ]
        filteredbridges = []
        slash16s = dict()

        for bridge in bridges:
            m = re.match(r'(\d+\.\d+)\.\d+\.\d+', bridge.ip)
            upper16 = m.group(1)
            if upper16 not in slash16s:
                filteredbridges.append(bridge)
                slash16s[upper16] = True
        return filteredbridges 

    def getBridgeByID(self, fp):
        """Return the bridge whose identity digest is fp, or None if no such
           bridge exists."""
        for _,_,_,subring in self.subrings:
            b = subring.getBridgeByID(fp)
            if b is not None:
                return b

        return self.bridgesByID.get(fp)

    def dumpAssignments(self, f, description=""):
        for b in self.bridges.itervalues():
            desc = [ description ]
            ident = b.getID()
            for tp,val,_,subring in self.subrings:
                if subring.getBridgeByID(ident):
                    desc.append("%s=%s"%(tp,val))
            f.write("%s %s\n"%( toHex(ident), " ".join(desc).strip()))

class FixedBridgeSplitter(BridgeHolder):
    """A bridgeholder that splits bridges up based on an hmac and assigns
       them to several sub-bridgeholders with equal probability.
    """
    def __init__(self, key, rings):
        self.hmac = get_hmac_fn(key, hex=True)
        self.rings = rings[:]
        for r in self.rings:
            assert(isinstance(r, BridgeHolder))

    def insert(self, bridge):
        # Grab the first 4 bytes
        digest = self.hmac(bridge.getID())
        pos = long( digest[:8], 16 )
        which = pos % len(self.rings)
        self.rings[which].insert(bridge)

    def clear(self):
        for r in self.rings:
            r.clear()

    def __len__(self):
        n = 0
        for r in self.rings:
            n += len(r)
        return n

    def dumpAssignments(self, f, description=""):
        for i,r in zip(xrange(len(self.rings)), self.rings):
            r.dumpAssignments(f, "%s ring=%s" % (description, i))

class UnallocatedHolder(BridgeHolder):
    """A pseudo-bridgeholder that ignores its bridges and leaves them
       unassigned.
    """
    def __init__(self):
        self.fingerprints = []

    def insert(self, bridge):
        logging.debug("Leaving %s unallocated", bridge.getConfigLine(True))
        if not bridge.fingerprint in self.fingerprints:
            self.fingerprints.append(bridge.fingerprint)

    def assignmentsArePersistent(self):
        return False

    def __len__(self):
        return len(self.fingerprints)

    def clear(self):
        self.fingerprints = []

    def dumpAssignments(self, f, description=""):
        db = bridgedb.Storage.getDB()
        allBridges = db.getAllBridges()
        for bridge in allBridges:
            if bridge.hex_key not in self.fingerprints:
                continue
            dist = bridge.distributor
            desc = [ description ]
            if dist.startswith(bridgedb.Bucket.PSEUDO_DISTRI_PREFIX):
                dist = dist.replace(bridgedb.Bucket.PSEUDO_DISTRI_PREFIX, "")
                desc.append("bucket=%s" % dist)
            elif dist != "unallocated":
                continue
            f.write("%s %s\n" % (bridge.hex_key, " ".join(desc).strip()))

class BridgeSplitter(BridgeHolder):
    """A BridgeHolder that splits incoming bridges up based on an hmac,
       and assigns them to sub-bridgeholders with different probabilities.
       Bridge-to-bridgeholder associations are recorded in a store.
    """
    def __init__(self, key):
        self.hmac = get_hmac_fn(key, hex=True)
        self.ringsByName = {}
        self.totalP = 0
        self.pValues = []
        self.rings = []
        self.pseudoRings = []
        self.statsHolders = []

    def __len__(self):
        n = 0
        for r in self.ringsByName.values():
            n += len(r)
        return n

    def addRing(self, ring, ringname, p=1):
        """Add a new bridgeholder.
           ring -- the bridgeholder to add.
           ringname -- a string representing the bridgeholder.  This is used
               to record which bridges have been assigned where in the store.
           p -- the relative proportion of bridges to assign to this
               bridgeholder.
        """
        assert isinstance(ring, BridgeHolder)
        self.ringsByName[ringname] = ring
        self.pValues.append(self.totalP)
        self.rings.append(ringname)
        self.totalP += p

    def addPseudoRing(self, ringname):
        """Add a pseudo ring to the list of pseudo rings.
        """
        self.pseudoRings.append(bridgedb.Bucket.PSEUDO_DISTRI_PREFIX + ringname)

    def addTracker(self, t):
        """Adds a statistics tracker that gets told about every bridge we see.
        """
        self.statsHolders.append(t)

    def clear(self):
        for r in self.ringsByName.values():
            r.clear()

    def insert(self, bridge):
        assert self.rings
        db = bridgedb.Storage.getDB()

        for s in self.statsHolders:
            s.insert(bridge)
        if not bridge.running:
            return

        bridgeID = bridge.getID()

        # Determine which ring to put this bridge in if we haven't seen it
        # before.
        pos = self.hmac(bridgeID)
        n = int(pos[:8], 16) % self.totalP
        pos = bisect.bisect_right(self.pValues, n) - 1
        assert 0 <= pos < len(self.rings)
        ringname = self.rings[pos]

        validRings = self.rings + self.pseudoRings

        ringname = db.insertBridgeAndGetRing(bridge, ringname, time.time(), 
                                             validRings)
        db.commit()

        # Pseudo distributors are always held in the "unallocated" ring
        if ringname in self.pseudoRings:
            ringname = "unallocated"

        ring = self.ringsByName.get(ringname)
        ring.insert(bridge)

    def dumpAssignments(self, f, description=""):
        for name,ring in self.ringsByName.iteritems():
            ring.dumpAssignments(f, "%s %s" % (description, name))

class BridgeBlock:
    """Base class that abstracts bridge blocking"""
    def __init__(self):
        pass

    def insert(self, fingerprint, blockingRule):
        raise NotImplementedError

    def clear(self):
        pass

    def assignmentsArePersistent(self):
        return True

class CountryBlock(BridgeBlock):
    """Countrywide bridge blocking"""
    def __init__(self):
        self.db = bridgedb.Storage.getDB()

    def clear(self):
        assert self.db
        self.db.cleanBridgeBlocks()
        self.db.commit()

    def insert(self, fingerprint, blockingRule):
        """ insert a country based blocking rule """
        assert self.db
        countryCode = blockingRule
        self.db.addBridgeBlock(fingerprint, countryCode)
        self.db.commit()

    def getBlockingCountries(self, fingerprint):
        """ returns a list of country codes where this fingerprint is blocked"""
        assert self.db
        if fingerprint is not None:
            return self.db.getBlockingCountries(fingerprint) 
