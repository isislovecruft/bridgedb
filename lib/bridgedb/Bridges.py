# BridgeDB by Nick Mathewson.
# Copyright (c) 2007, The Tor Project, Inc.
# See LICENSE for licensing informatino

import binascii
import bisect
import hmac
import sha
import socket
import struct
import time

HEX_FP_LEN = 40
ID_LEN = 20

DIGESTMOD = sha
HEX_DIGEST_LEN = 40
DIGEST_LEN = 20

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
    except socekt.error:
        return False
    else:
        return True

def is_valid_fingerprint(fp):
    if len(fp) != HEX_FP_LEN:
        return False
    try:
        toHex(fp)
    except TypeError:
        return False
    else:
        return True

toHex = binascii.b2a_hex
fromHex = binascii.a2b_hex

def get_hmac(k,v):
    h = hmac.new(k, v, digestmod=DIGESTMOD)
    return h.digest()

def get_hmac_fn(k, hex=True):
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
    for pos in xrange(0, len(s), size):
        yield s[pos:pos+size]

class Bridge:
    def __init__(self, nickname, ip, orport, fingerprint=None, id_digest=None):
        self.nickname = nickname
        self.ip = ip
        self.orport = orport
        if id_digest is not None:
            assert fingerprint is None
            if len(id_digest) != DIGEST_LEN:
                raise TypeError("Bridge with invalid ID")
            self.fingerprint = toHex(id_digest)
        elif fingerprint is not None:
            if not is_valid_fingerprint(fromHex(fingerprint)):
                raise TypeError("Bridge with invalid fingerprint")
            self.fingerprint = fingerprint.lower()
        else:
            raise TypeError("Bridge with no ID")

    def getID(self):
        return fromHex(self.fingerprint)

    def __repr__(self):
        return "Bridge(%r,%r,%d,%r)"%(
            self.nickname, self.ip, self.orport, self.fingerprint)

    def getConfigLine(self):
        return "bridge %s:%d %s" % (self.ip, self.orport, self.fingerprint)

    def assertOK(self):
        assert is_valid_ip(self.ip)
        assert is_valid_fingerprint(self.fingerprint)
        assert 1 <= self.orport <= 65535

def parseDescFile(f, bridge_purpose='bridge'):
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

class BridgeHolder:
    def insert(self, bridge):
        raise NotImplemented

    def assignmentsArePersistent(self):
        return True

class BridgeRing(BridgeHolder):
    def __init__(self, key):
        self.bridges = {}
        self.bridgesByID = {}
        self.hmac = get_hmac_fn(key, hex=False)
        self.isSorted = False
        self.sortedKeys = []

    def insert(self, bridge):
        id = bridge.getID()
        pos = self.hmac(id)
        if not self.bridges.has_key(pos):
            self.sortedKeys.append(pos)
            self.isSorted = False
        self.bridges[pos] = bridge
        self.bridgesByID[id] = bridge

    def sort(self):
        if not self.isSorted:
            self.sortedKeys.sort()
            self.isSorted = True

    def _getBridgeKeysAt(self, pos, N=1):
        assert len(pos) == DIGEST_LEN
        if N >= len(self.sortedKeys):
            return self.sortedKeys
        if not self.isSorted:
            self.sort()
        idx = bisect.bisect_left(self.sortedKeys, pos)
        r = self.sortedKeys[idx:idx+N]
        if len(r) < N:
            # wrap around as needed.
            r.extend(self.sortedKeys[:N - len(r)])
        assert len(r) == N
        return r

    def getBridges(self, pos, N=1):
        keys = self._getBridgeKeysAt(pos, N)
        keys.sort()
        return [ self.bridges[k] for k in keys ]

    def getBridgeByID(self, fp):
        return self.bridgesByID.get(fp)

    def __len__(self):
        return len(self.bridges)


class LogDB:
    def __init__(self, kwd, db, logfile):
        self._kwd = kwd
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
            self._logfile.write("%s: [%r] = [%r]\n"%(self._kwd, k, v))
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

def FixedBridgeSplitter(BridgeHolder):
    def __init__(self, key, rings):
        self.hmac = get_mac_fn(key, hex=True)
        self.rings = rings[:]
        for r in self.rings:
            assert(isinstance(r, BridgeHolder))

    def insert(self, bridge):
        # Grab the first 4 bytes
        digest = self.hmac(bridge.getID())
        pos = long( digest[:8], 16 )
        which = pos % len(self.rings)
        self.ring[which].insert(bridge)

class UnallocatedHolder(BridgeHolder):
    def insert(self, bridge):
        pass

    def assignmentsArePersistent(self):
        return False

class BridgeTracker:
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

def BridgeSplitter(BridgeHolder):
    def __init__(self, key, store):
        self.hmac = hmac.new(key, digestmod=DIGESTMOD)
        self.store = store
        self.ringsByName = {}
        self.totalP = 0
        self.pValues = []
        self.rings = []
        self.statsHolders = []

    def addRing(self, ring, ringname, p=1):
        assert isinstance(ring, BridgeHolder)
        self.ringsByName[ringname] = ring
        self.pValues.append(self.totalP)
        self.rings.append(ringname)
        self.totalP += p

    def addTracker(self, t):
        self.statsHolders.append(t)

    def insert(self, bridge):
        assert self.rings
        for s in self.statsHolders:
            s.insert(bridge)
        bridgeID = bridge.getID()
        ringname = self.store.get(bridgeID, "")
        ring = self.ringsByName.get(ringname)
        if ring is not None:
            ring.insert(bridge)
        else:
            pos = self.hmac(bridgeID)
            n = int(pos[:8], 16) % self.totalP
            pos = bisect.bisect_right(self.pValues, p) - 1
            assert 0 <= pos < len(self.rings)
            ringname = self.rings[pos]
            ring = self.ringsByName.get(ringname)
            if ring.assignmentsArePersistent():
                self.store[bridgeID] = ringname
            ring.insert(bridge)

if __name__ == '__main__':
    import sys
    br = BridgeRing("hello")
    for fname in sys.argv[1:]:
        f = open(fname)
        for bridge in parseDescFile(f):
            br.insert(bridge)

