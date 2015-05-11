# BridgeDB by Nick Mathewson.
# Copyright (c) 2007-2009, The Tor Project, Inc.
# See LICENSE for licensing information

import calendar
import os
import logging
import binascii
import sqlite3
import time
import hashlib
from contextlib import GeneratorContextManager
from functools import wraps
from ipaddr import IPAddress, IPv6Address, IPv4Address
import sys

from twisted.internet import reactor

import bridgedb.Stability as Stability
from bridgedb.Stability import BridgeHistory
import threading

toHex = binascii.b2a_hex
fromHex = binascii.a2b_hex
HEX_ID_LEN = 40

def _escapeValue(v):
    return "'%s'" % v.replace("'", "''")

def timeToStr(t):
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(t))
def strToTime(t):
    return calendar.timegm(time.strptime(t, "%Y-%m-%d %H:%M"))

#  The old DB system was just a key->value mapping DB, with special key
#  prefixes to indicate which database they fell into.
#
#     sp|<ID> -- given to bridgesplitter; maps bridgeID to ring name.
#     em|<emailaddr> -- given to emailbaseddistributor; maps email address
#            to concatenated ID.
#     fs|<ID> -- Given to BridgeTracker, maps to time when a router was
#            first seen (YYYY-MM-DD HH:MM)
#     ls|<ID> -- given to bridgetracker, maps to time when a router was
#            last seen (YYYY-MM-DD HH:MM)
#
# We no longer want to use em| at all, since we're not doing that kind
# of persistence any more.

# Here is the SQL schema.
SCHEMA2_SCRIPT = """
 CREATE TABLE Config (
     key PRIMARY KEY NOT NULL,
     value
 );

 CREATE TABLE Bridges (
     id INTEGER PRIMARY KEY NOT NULL,
     hex_key,
     address,
     or_port,
     distributor,
     first_seen,
     last_seen
 );

 CREATE UNIQUE INDEX BridgesKeyIndex ON Bridges ( hex_key );

 CREATE TABLE EmailedBridges (
     email PRIMARY KEY NOT NULL,
     when_mailed
 );

 CREATE INDEX EmailedBridgesWhenMailed on EmailedBridges ( email );

 CREATE TABLE BlockedBridges (
     id INTEGER PRIMARY KEY NOT NULL,
     hex_key,
     blocking_country
 );

 CREATE INDEX BlockedBridgesBlockingCountry on BlockedBridges(hex_key);

 CREATE TABLE WarnedEmails (
     email PRIMARY KEY NOT NULL,
     when_warned
 );

 CREATE INDEX WarnedEmailsWasWarned on WarnedEmails ( email );

 INSERT INTO Config VALUES ( 'schema-version', 2 ); 
"""

SCHEMA_2TO3_SCRIPT = """
 CREATE TABLE BridgeHistory (
     fingerprint PRIMARY KEY NOT NULL,
     address,
     port INT,
     weightedUptime LONG,
     weightedTime LONG,
     weightedRunLength LONG,
     totalRunWeights DOUBLE,
     lastSeenWithDifferentAddressAndPort LONG,
     lastSeenWithThisAddressAndPort LONG,
     lastDiscountedHistoryValues LONG,
     lastUpdatedWeightedTime LONG
 );

 CREATE INDEX BridgeHistoryIndex on BridgeHistory ( fingerprint );

 INSERT OR REPLACE INTO Config VALUES ( 'schema-version', 3 ); 
 """
SCHEMA3_SCRIPT = SCHEMA2_SCRIPT + SCHEMA_2TO3_SCRIPT

class BridgeData:
    """Value class carrying bridge information:
       hex_key      - The unique hex key of the given bridge
       address      - Bridge IP address
       or_port      - Bridge TCP port
       distributor  - The distributor (or pseudo-distributor) through which 
                      this bridge is being announced
       first_seen   - When did we first see this bridge online?
       last_seen    - When was the last time we saw this bridge online?
    """
    def __init__(self, hex_key, address, or_port, distributor="unallocated", 
                 first_seen="", last_seen=""):
        self.hex_key = hex_key
        self.address = address
        self.or_port = or_port
        self.distributor = distributor
        self.first_seen = first_seen
        self.last_seen = last_seen

class Database(object):
    def __init__(self, sqlite_fname):
        self._conn = openDatabase(sqlite_fname)
        self._cur = self._conn.cursor()
        self.sqlite_fname = sqlite_fname

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        #print "Closing DB"
        self._cur.close()
        self._conn.close()

    def insertBridgeAndGetRing(self, bridge, setRing, seenAt, validRings,
                               defaultPool="unallocated"):
        '''Updates info about bridge, setting ring to setRing if none was set.
           Also sets distributor to `defaultPool' if the bridge was found in
           the database, but its distributor isn't valid anymore.

           Returns the name of the distributor the bridge is assigned to.
        '''
        cur = self._cur

        t = timeToStr(seenAt)
        h = bridge.fingerprint
        assert len(h) == HEX_ID_LEN

        cur.execute("SELECT id, distributor "
                    "FROM Bridges WHERE hex_key = ?", (h,))
        v = cur.fetchone()
        if v is not None:
            i, ring = v
            # Check if this is currently a valid ring name. If not, move back
            # into default pool.
            if ring not in validRings:
                ring = defaultPool
            # Update last_seen, address, port and (possibly) distributor.
            cur.execute("UPDATE Bridges SET address = ?, or_port = ?, "
                        "distributor = ?, last_seen = ? WHERE id = ?",
                        (str(bridge.address), bridge.orPort, ring,
                         timeToStr(seenAt), i))
            return ring
        else:
            # Insert it.
            cur.execute("INSERT INTO Bridges (hex_key, address, or_port, "
                        "distributor, first_seen, last_seen) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (h, str(bridge.address), bridge.orPort, setRing, t, t))
            return setRing

    def cleanEmailedBridges(self, expireBefore):
        cur = self._cur
        t = timeToStr(expireBefore)
        cur.execute("DELETE FROM EmailedBridges WHERE when_mailed < ?", (t,))

    def getEmailTime(self, addr):
        addr = hashlib.sha1(addr).hexdigest()
        cur = self._cur
        cur.execute("SELECT when_mailed FROM EmailedBridges WHERE email = ?", (addr,))
        v = cur.fetchone()
        if v is None:
            return None
        return strToTime(v[0])

    def setEmailTime(self, addr, whenMailed):
        addr = hashlib.sha1(addr).hexdigest()
        cur = self._cur
        t = timeToStr(whenMailed)
        cur.execute("INSERT OR REPLACE INTO EmailedBridges "
                    "(email,when_mailed) VALUES (?,?)", (addr, t))

    def getAllBridges(self):
        """Return a list of BridgeData value classes of all bridges in the
           database
        """
        retBridges = []
        cur = self._cur
        cur.execute("SELECT hex_key, address, or_port, distributor, "
                    "first_seen, last_seen  FROM Bridges")
        for b in cur.fetchall():
            bridge = BridgeData(b[0], b[1], b[2], b[3], b[4], b[5])
            retBridges.append(bridge)

        return retBridges

    def getUnallocated(self, prefix):
        """Get all bridges in the database which are unallocated.

        :param str prefix: The string prefix for the names of unallocated
            bridges.
        :rtype: dict
        :returns: A mapping from unallocated "bucket" names (which should
            start with the **prefix**) to the :class:`BridgeData`s within that
            unallocated "bucket".
        """
        unallocated = {}
        cur = self._cur
        cur.execute("SELECT hex_key, address, or_port, distributor, "
                    "first_seen, last_seen  FROM Bridges")
        for b in cur.fetchall():
            channel = b[3]
            if channel.startswith(prefix):
                channel = channel[len(prefix):]
            elif channel != "unallocated":
                continue

            if not channel in unallocated:
                unallocated[channel] = []
            unallocated[channel].append(BridgeData(b[0], b[1], b[2],
                                                   b[3], b[4], b[5]))
        return unallocated

    def getBridgesForDistributor(self, distributor):
        """Return a list of BridgeData value classes of all bridges in the
           database that are allocated to distributor 'distributor'
        """
        retBridges = []
        cur = self._cur
        cur.execute("SELECT hex_key, address, or_port, distributor, "
                    "first_seen, last_seen FROM Bridges WHERE "
                    "distributor = ?", (distributor, ))
        for b in cur.fetchall():
            bridge = BridgeData(b[0], b[1], b[2], b[3], b[4], b[5])
            retBridges.append(bridge)

        return retBridges

    def updateDistributorForHexKey(self, distributor, hex_key):
        cur = self._cur
        cur.execute("UPDATE Bridges SET distributor = ? WHERE hex_key = ?",
                    (distributor, hex_key))

    def getWarnedEmail(self, addr):
        addr = hashlib.sha1(addr).hexdigest()
        cur = self._cur
        cur.execute("SELECT * FROM WarnedEmails WHERE email = ?", (addr,))
        v = cur.fetchone()
        if v is None:
            return False
        return True

    def setWarnedEmail(self, addr, warned=True, whenWarned=time.time()):
        addr = hashlib.sha1(addr).hexdigest()
        t = timeToStr(whenWarned)
        cur = self._cur
        if warned == True:
            cur.execute("INSERT INTO WarnedEmails"
                        "(email,when_warned) VALUES (?,?)", (addr, t,))
        elif warned == False:
            cur.execute("DELETE FROM WarnedEmails WHERE email = ?", (addr,))

    def cleanWarnedEmails(self, expireBefore):
        cur = self._cur
        t = timeToStr(expireBefore)

        cur.execute("DELETE FROM WarnedEmails WHERE when_warned < ?", (t,))

    def updateIntoBridgeHistory(self, bh):
        cur = self._cur
        cur.execute("INSERT OR REPLACE INTO BridgeHistory values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (bh.fingerprint, str(bh.ip), bh.port,
                bh.weightedUptime, bh.weightedTime, bh.weightedRunLength,
                bh.totalRunWeights, bh.lastSeenWithDifferentAddressAndPort,
                bh.lastSeenWithThisAddressAndPort, bh.lastDiscountedHistoryValues,
                bh.lastUpdatedWeightedTime))
        return bh

    def delBridgeHistory(self, fp):
        cur = self._cur
        cur.execute("DELETE FROM BridgeHistory WHERE fingerprint = ?", (fp,))

    def getBridgeHistory(self, fp):
        cur = self._cur
        cur.execute("SELECT * FROM BridgeHistory WHERE fingerprint = ?", (fp,))
        h = cur.fetchone()
        if h is None: 
            return
        return BridgeHistory(h[0],IPAddress(h[1]),h[2],h[3],h[4],h[5],h[6],h[7],h[8],h[9],h[10])

    def getAllBridgeHistory(self):
        cur = self._cur
        v = cur.execute("SELECT * FROM BridgeHistory")
        if v is None: return
        fp = {}
        for h in v:
            yield BridgeHistory(h[0],IPAddress(h[1]),h[2],h[3],h[4],h[5],h[6],h[7],h[8],h[9],h[10])

    def getBridgesLastUpdatedBefore(self, statusPublicationMillis):
        cur = self._cur
        v = cur.execute("SELECT * FROM BridgeHistory WHERE lastUpdatedWeightedTime < ?",
                        (statusPublicationMillis,))
        if v is None: return
        for h in v:
            yield BridgeHistory(h[0],IPAddress(h[1]),h[2],h[3],h[4],h[5],h[6],h[7],h[8],h[9],h[10])


def openDatabase(sqlite_file):
    conn = sqlite3.Connection(sqlite_file)
    cur = conn.cursor()
    try:
        try:
            cur.execute("SELECT value FROM Config WHERE key = 'schema-version'")
            val, = cur.fetchone()
            if val == 2:
                logging.info("Adding new table BridgeHistory")
                cur.executescript(SCHEMA_2TO3_SCRIPT)
            elif val != 3:
                logging.warn("Unknown schema version %s in database.", val)
        except sqlite3.OperationalError:
            logging.warn("No Config table found in DB; creating tables")
            cur.executescript(SCHEMA3_SCRIPT)
            conn.commit()
    finally:
        cur.close()
    return conn


class DBGeneratorContextManager(GeneratorContextManager):
    """Helper for @contextmanager decorator.

    Overload __exit__() so we can call the generator many times
    """
    def __exit__(self, type, value, traceback):
        """Handle exiting a with statement block

        Progress generator or throw exception

        Significantly based on contextlib.py

        :throws: `RuntimeError` if the generator doesn't stop after
            exception is thrown
        """
        if type is None:
            try:
                self.gen.next()
            except StopIteration:
                return
            return
        else:
            if value is None:
                # Need to force instantiation so we can reliably
                # tell if we get the same exception back
                value = type()
            try:
                self.gen.throw(type, value, traceback)
                raise RuntimeError("generator didn't stop after throw()")
            except StopIteration, exc:
                # Suppress the exception *unless* it's the same exception that
                # was passed to throw().  This prevents a StopIteration
                # raised inside the "with" statement from being suppressed
                return exc is not value
            except:
                # only re-raise if it's *not* the exception that was
                # passed to throw(), because __exit__() must not raise
                # an exception unless __exit__() itself failed.  But throw()
                # has to raise the exception to signal propagation, so this
                # fixes the impedance mismatch between the throw() protocol
                # and the __exit__() protocol.
                #
                if sys.exc_info()[1] is not value:
                    raise

def contextmanager(func):
    """Decorator to for :func:`Storage.getDB()`

    Define getDB() for use by with statement content manager
    """
    @wraps(func)
    def helper(*args, **kwds):
        return DBGeneratorContextManager(func(*args, **kwds))
    return helper

_DB_FNAME = None
_LOCK = None
_LOCKED = 0
_OPENED_DB = None
_REFCOUNT = 0

def clearGlobalDB():
    """Start from scratch

    This is currently only used in unit tests.
    """
    global _DB_FNAME
    global _LOCK
    global _LOCKED
    global _OPENED_DB

    _DB_FNAME = None
    _LOCK = None
    _LOCKED = 0
    _OPENED_DB = None
    _REFCOUNT = 0

def initializeDBLock():
    """Create the lock

    This must be called before the first database query
    """
    global _LOCK

    if not _LOCK:
        _LOCK = threading.RLock()
    assert _LOCK

def setDBFilename(sqlite_fname):
    global _DB_FNAME
    _DB_FNAME = sqlite_fname

@contextmanager
def getDB(block=True):
    """Generator: Return a usable database handler

    Always return a :class:`bridgedb.Storage.Database` that is
    usable within the current thread. If a connection already exists
    and it was created by the current thread, then return the
    associated :class:`bridgedb.Storage.Database` instance. Otherwise,
    create a new instance, blocking until the existing connection
    is closed, if applicable.

    Note: This is a blocking call (by default), be careful about
        deadlocks!

    :rtype: :class:`bridgedb.Storage.Database`
    :returns: An instance of :class:`bridgedb.Storage.Database` used to
        query the database
    """
    global _DB_FNAME
    global _LOCK
    global _LOCKED
    global _OPENED_DB
    global _REFCOUNT

    assert _LOCK
    try:
        own_lock = _LOCK.acquire(block)
        if own_lock:
            _LOCKED += 1

            if not _OPENED_DB:
                assert _REFCOUNT == 0
                _OPENED_DB = Database(_DB_FNAME)

            _REFCOUNT += 1
            yield _OPENED_DB
        else:
            yield False
    finally:
        assert own_lock
        try:
            _REFCOUNT -= 1
            if _REFCOUNT == 0:
                _OPENED_DB.close()
                _OPENED_DB = None
        finally:
            _LOCKED -= 1
            _LOCK.release()

def dbIsLocked():
    return _LOCKED != 0

def dumpBridgesToFile(filename, bridges, collectTimestamps=False):
    """Dump a list of given **bridges** into **filename**."""
    logging.debug("Dumping bridge assignments to file: %r" % filename)
    # Get the bridge histories and sort by weighted fractional uptime
    bridgeHistories = []
    for b in bridges:
        if collectTimestamps:
            with bridgedb.Storage.getDB() as db:
                bh = db.getBridgeHistory(b.hex_key)
                if bh: bridgeHistories.append(bh)

    bridgeHistories.sort(lambda x,y: cmp(x.weightedFractionalUptime,
                                         y.weightedFractionalUptime))
    try:
        with open(filename, 'w') as f:
            if collectTimestamps:
                for bh in bridgeHistories:
                    days = bh.tosa / long(60*60*24)
                    line = "%s:%s %s\t(%d days at this address)\n" % \
                           (bh.ip, bh.port, bh.fingerprint, days)
                    f.write(line + '\n')

            for bridge in bridges:
                line = "%s:%d %s\n" % \
                       (bridge.address, bridge.or_port, bridge.hex_key)
                f.write(line)

            f.flush()
    except (IOError, OSError) as error:
        logging.error("Error writing to %s: %s" % (filename, error))

def dumpBridges(collectTimestamps=False):
    """Dump all known file distributors to files, sorted by distributor."""
    logging.info("Dumping all distributors to files.")

    from bridgedb.unallocated import BUCKET_PREFIX

    with bridgedb.Storage.getDB() as db:
        allBridges = db.getAllBridges()

    bridges = {}
    for bridge in allBridges:
        # Be safe. Replace all '/' in distributor names
        distributor = bridge.distributor.replace('/', '_')
        if distributor.startswith(BUCKET_PREFIX):
            distributor = distributor[len(BUCKET_PREFIX):]
        if not distributor in bridges:
            bridges[distributor] = []
        bridges[distributor].append(bridge)

    for distributor, brdgs in bridges.items():
        filename = distributor + "-" + time.strftime("%Y-%m-%d") + ".brdgs"
        reactor.callInThread(dumpBridgesToFile, filename, brdgs,
                             collectTimestamps=False)
