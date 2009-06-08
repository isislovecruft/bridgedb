# BridgeDB by Nick Mathewson.
# Copyright (c) 2007, The Tor Project, Inc.
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

    if not re.match(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', ip):
        # inet_aton likes "1.2" as a synonym for "0.0.1.2".  We don't.
        return False
    try:
        socket.inet_aton(ip)
    except socket.error:
        return False
    else:
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
    def __init__(self, nickname, ip, orport, fingerprint=None, id_digest=None):
        """Create a new Bridge.  One of fingerprint and id_digest must be
           set."""
        self.nickname = nickname
        self.ip = ip
        self.orport = orport
        self.running = self.stable = None
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
        return "Bridge(%r,%r,%d,%r)"%(
            self.nickname, self.ip, self.orport, self.fingerprint)

    def getConfigLine(self):
        """Return a line describing this bridge for inclusion in a torrc."""
        return "bridge %s:%d %s" % (self.ip, self.orport, self.fingerprint)

    def assertOK(self):
        assert is_valid_ip(self.ip)
        assert is_valid_fingerprint(self.fingerprint)
        assert 1 <= self.orport <= 65535

    def setStatus(self, running=None, stable=None):
        if running is not None:
            self.running = running
        if stable is not None:
            self.stable = stable


def parseDescFile(f, bridge_purpose='bridge'):
    """Generator. Parses a cached-descriptors file 'f', and yields a Bridge
       object for every entry whose purpose matches bridge_purpose.
    """
    nickname = ip = orport = fingerprint = purpose = None

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
        elif line.startswith("router-signature"):
            purposeMatches = (purpose == bridge_purpose or
                              bridge_purpose is None)
            if purposeMatches and nickname and ip and orport and fingerprint:
                b = Bridge(nickname, ip, orport, fingerprint)
                b.assertOK()
                yield b
            nickname = ip = orport = fingerprint = purpose = None

def parseStatusFile(f):
    """DOCDOC"""
    result = None
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

class BridgeHolder:
    """Abstract base class for all classes that hold bridges."""
    def insert(self, bridge):
        raise NotImplemented()

    def clear(self):
        pass

    def assignmentsArePersistent(self):
        return True

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
        self.sortedKeys = []

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
        logging.debug("Adding %s to %s", bridge.getConfigLine(), self.name)

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

    def getBridges(self, pos, N=1):
        """Return the N bridges appearing in the ring after position pos"""
        forced = []
        for _,_,count,subring in self.subrings:
            if len(subring) < count:
                count = len.subring
            forced.extend(subring._getBridgeKeysAt(pos, count))

        keys = [ ]
        for k in forced + self._getBridgeKeysAt(pos, N):
            if k not in keys:
                keys.append(k)
        keys = keys[:N]
        keys.sort()
        return [ self.bridges[k] for k in keys ]

    def getBridgeByID(self, fp):
        """Return the bridge whose identity digest is fp, or None if no such
           bridge exists."""
        for _,_,_,subring in self.subrings:
            b = subring.getBridgeByID(fp)
            if b is not None:
                return b

        return self.bridgesByID.get(fp)

class LogDB:
    """Wraps a database object and records all modifications to a
       human-readable logfile."""
    def __init__(self, kwd, db, logfile):
        if kwd:
            self._kwd = "%s: "%kwd
        else:
            self._kwd = ""
        self._db = db
        self._logfile = logfile
    def __delitem__(self, k):
        self._logfile.write("%s: del[%r]\n"%(self._kwd, k))
        del self._db[k]
    def __setitem__(self, k, v):
        self._logfile.write("%s: [%r] = [%r]\n"%(self._kwd, k, v))
        self._db[k] = v
    def setdefault(self, k, v):
        try:
            return self._db[k]
        except KeyError:
            self._logfile.write("%s[%r] = [%r]\n"%(self._kwd, k, v))
            self._db[k] = v
            return v
    def __len__(self):
        return len(self._db)
    def __getitem__(self, k):
        return self._db[k]
    def has_key(self, k):
        return self._db.has_key(k)
    def get(self, k, v=None):
        return self._db.get(k, v)
    def keys(self):
        return self._db.keys()


class PrefixStore:
    """Wraps a database object and prefixes the keys in all requests with
       'prefix'.  This is used to multiplex several key->value mappings
       onto a single database."""
    def __init__(self, store, prefix):
        self._d = store
        self._p = prefix
    def __setitem__(self, k, v):
        self._d[self._p+k] = v
    def __delitem__(self, k):
        del self._d[self._p+k]
    def __getitem__(self, k):
        return self._d[self._p+k]
    def has_key(self, k):
        return self._d.has_key(self._p+k)
    def get(self, k, v=None):
        return self._d.get(self._p+k, v)
    def setdefault(self, k, v):
        return self._d.setdefault(self._p+k, v)
    def keys(self):
        n = len(self._p)
        return [ k[n:] for k in self._d.keys() if k.startswith(self._p) ]

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


class UnallocatedHolder(BridgeHolder):
    """A pseudo-bridgeholder that ignores its bridges and leaves them
       unassigned.
    """
    def insert(self, bridge):
        logging.debug("Leaving %s unallocated", bridge.getConfigLine())

    def assignmentsArePersistent(self):
        return False

    def __len__(self):
        return 0

class BridgeTracker:
    """A stats tracker that records when we first saw and most recently
       saw each bridge.
    """
    def __init__(self, firstSeenStore, lastSeenStore):
        self.firstSeenStore = firstSeenStore
        self.lastSeenStore = lastSeenStore

    def insert(self, bridge):
        #XXXX is this really sane?  Should we track minutes? hours?
        now = time.strftime("%Y-%m-%d %H:%M", time.gmtime())
        bridgeID = bridge.getID()
        # The last-seen time always gets updated
        self.lastSeenStore[bridgeID] = now
        # The first-seen time only gets updated if it wasn't already set.
        self.firstSeenStore.setdefault(bridgeID, now)

class BridgeSplitter(BridgeHolder):
    """A BridgeHolder that splits incoming bridges up based on an hmac,
       and assigns them to sub-bridgeholders with different probabilities.
       Bridge-to-bridgeholder associations are recorded in a store.
    """
    def __init__(self, key, store):
        self.hmac = get_hmac_fn(key, hex=True)
        self.store = store
        self.ringsByName = {}
        self.totalP = 0
        self.pValues = []
        self.rings = []
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

    def addTracker(self, t):
        """Adds a statistics tracker that gets told about every bridge we see.
        """
        self.statsHolders.append(t)

    def clear(self):
        for r in self.ringsByName.values():
            r.clear()

    def insert(self, bridge):
        assert self.rings
        for s in self.statsHolders:
            s.insert(bridge)
        if bridge.running == False or bridge.running == None:
            return

        bridgeID = bridge.getID()
        ringname = self.store.get(bridgeID, "")
        ring = self.ringsByName.get(ringname)
        if ring is not None:
            ring.insert(bridge)
        else:
            pos = self.hmac(bridgeID)
            n = int(pos[:8], 16) % self.totalP
            pos = bisect.bisect_right(self.pValues, n) - 1
            assert 0 <= pos < len(self.rings)
            ringname = self.rings[pos]
            ring = self.ringsByName.get(ringname)
            if ring.assignmentsArePersistent():
                self.store[bridgeID] = ringname
            ring.insert(bridge)

