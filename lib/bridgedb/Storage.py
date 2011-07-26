# BridgeDB by Nick Mathewson.
# Copyright (c) 2007-2009, The Tor Project, Inc.
# See LICENSE for licensing information

import calendar
import os
import logging
import binascii
import sqlite3
import time
import sha

toHex = binascii.b2a_hex
fromHex = binascii.a2b_hex
HEX_ID_LEN = 40

def _escapeValue(v):
    return "'%s'" % v.replace("'", "''")

def timeToStr(t):
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(t))
def strToTime(t):
    return calendar.timegm(time.strptime(t, "%Y-%m-%d %H:%M"))

class SqliteDict:
    """
       A SqliteDict wraps a SQLite table and makes it look like a
       Python dictionary.  In addition to the single key and value
       columns, there can be a number of "fixed" columns, such that
       the dictionary only contains elements of the table where the
       fixed columns are set appropriately.
    """
    def __init__(self, conn, cursor, table, fixedcolnames, fixedcolvalues,
                 keycol, valcol):
        assert len(fixedcolnames) == len(fixedcolvalues)
        self._conn = conn
        self._cursor = cursor
        keys = ", ".join(fixedcolnames+(keycol,valcol))
        vals = "".join("%s, "%_escapeValue(v) for v in fixedcolvalues)
        constraint = "WHERE %s = ?"%keycol
        if fixedcolnames:
            constraint += "".join(
                " AND %s = %s"%(c,_escapeValue(v))
                for c,v in zip(fixedcolnames, fixedcolvalues))

        self._getStmt = "SELECT %s FROM %s %s"%(valcol,table,constraint)
        self._delStmt = "DELETE FROM %s %s"%(table,constraint)
        self._setStmt = "INSERT OR REPLACE INTO %s (%s) VALUES (%s?, ?)"%(
            table, keys, vals)

        constraint = " AND ".join("%s = %s"%(c,_escapeValue(v))
                for c,v in zip(fixedcolnames, fixedcolvalues))
        if constraint:
            whereClause = " WHERE %s"%constraint
        else:
            whereClause = ""

        self._keysStmt = "SELECT %s FROM %s%s"%(keycol,table,whereClause)

    def __setitem__(self, k, v):
        self._cursor.execute(self._setStmt, (k,v))
    def __delitem__(self, k):
        self._cursor.execute(self._delStmt, (k,))
        if self._cursor.rowcount == 0:
            raise KeyError(k)
    def __getitem__(self, k):
        self._cursor.execute(self._getStmt, (k,))
        val = self._cursor.fetchone()
        if val == None:
            raise KeyError(k)
        else:
            return val[0]
    def has_key(self, k):
        self._cursor.execute(self._getStmt, (k,))
        return self._cursor.rowcount != 0
    def get(self, k, v=None):
        self._cursor.execute(self._getStmt, (k,))
        val = self._cursor.fetchone()
        if val == None:
            return v
        else:
            return val[0]
    def setdefault(self, k, v):
        try:
            r = self[k]
        except KeyError:
            r = self[k] = v
        return r
    def keys(self):
        self._cursor.execute(self._keysStmt)
        return [ key for (key,) in self._cursor.fetchall() ]

    def commit(self):
        self._conn.commit()
    def rollback(self):
        self._conn.rollback()


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

class Database:
    def __init__(self, sqlite_fname, db_fname=None):
        if db_fname is None:
            self._conn = openDatabase(sqlite_fname)
        else:
            self._conn = openOrConvertDatabase(sqlite_fname, db_fname)
        self._cur = self._conn.cursor()

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
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
                        (bridge.ip, bridge.orport, ring, timeToStr(seenAt), i))
            return ring
        else:
            # Insert it.
            cur.execute("INSERT INTO Bridges (hex_key, address, or_port, "
                        "distributor, first_seen, last_seen) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (h, bridge.ip, bridge.orport, setRing, t, t))
            return setRing

    def cleanEmailedBridges(self, expireBefore):
        cur = self._cur
        t = timeToStr(expireBefore)

        cur.execute("DELETE FROM EmailedBridges WHERE when_mailed < ?", (t,))

    def getEmailTime(self, addr):
        addr = sha.new(addr).hexdigest()
        cur = self._cur
        cur.execute("SELECT when_mailed FROM EmailedBridges WHERE "
                    "email = ?", (addr,))
        v = cur.fetchone()
        if v is None:
            return None
        return strToTime(v[0])

    def setEmailTime(self, addr, whenMailed):
        addr = sha.new(addr).hexdigest()
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

    def addBridgeBlock(self, fingerprint, countryCode):
        cur = self._cur
        cur.execute("INSERT OR REPLACE INTO BlockedBridges "
                    "(hex_key,blocking_country) VALUES (?,?)",
                    (fingerprint, countryCode))

    def delBridgeBlock(self, fingerprint, countryCode):
        cur = self._cur
        cur.execute("DELETE FROM BlockedBridges WHERE hex_key = ? "
                    "AND blocking_country = ?", (fingerprint, countryCode))

    def cleanBridgeBlocks(self):
        cur = self._cur
        cur.execute("DELETE FROM BlockedBridges")

    def getBlockingCountries(self, fingerprint):
        cur = self._cur
        cur.execute("SELECT hex_key, blocking_country FROM BlockedBridges WHERE hex_key = ? ",
                    (fingerprint,))
        v = cur.fetchall()
        if v is None:
            return None

        # return list of country-codes
        return [ str(result[1]) for (result) in v ]

    def getBlockedBridges(self, countryCode):
        cur = self._cur
        cur.execute("SELECT hex_key, blocking_country FROM BlockedBridges WHERE blocking_country = ? ",
                    (countryCode,))
        v = cur.fetchall()
        if v is None:
            return None
        # return list of fingerprints
        return [ str(result[0]) for (result) in v ]

    def isBlocked(self, fingerprint, countryCode):
        cur = self._cur
        cur.execute("SELECT hex_key, blocking_country FROM BlockedBridges WHERE "
                    "hex_key = ? AND blocking_country = ?",
                    (fingerprint, countryCode))
        v = cur.fetchone()
        if v is None:
            return False
        return True 

    def getWarnedEmail(self, addr):
        addr = sha.new(addr).hexdigest()
        cur = self._cur
        cur.execute("SELECT * FROM WarnedEmails WHERE "
                    " email = ?", (addr,))
        v = cur.fetchone()
        if v is None:
            return False
        return True

    def setWarnedEmail(self, addr, warned=True, whenWarned=time.time()):
        addr = sha.new(addr).hexdigest()
        t = timeToStr(whenWarned)
        cur = self._cur
        if warned == True:
            cur.execute("INSERT INTO WarnedEmails"
                        "(email,when_warned) VALUES (?,?)", (addr, t,))
        elif warned == False:
            cur.execute("DELETE FROM WarnedEmails WHERE "
                        "email = ?", (addr,))

    def cleanWarnedEmails(self, expireBefore):
        cur = self._cur
        t = timeToStr(expireBefore)

        cur.execute("DELETE FROM WarnedEmails WHERE when_warned < ?", (t,))

def openDatabase(sqlite_file):
    conn = sqlite3.Connection(sqlite_file)
    cur = conn.cursor()
    try:
        try:
            cur.execute("SELECT value FROM Config WHERE key = 'schema-version'")
            val, = cur.fetchone()
            if val != 2:
                logging.warn("Unknown schema version %s in database.", val)
        except sqlite3.OperationalError:
            logging.warn("No Config table found in DB; creating tables")
            cur.executescript(SCHEMA2_SCRIPT)
            conn.commit()
    finally:
        cur.close()
    return conn


def openOrConvertDatabase(sqlite_file, db_file):
    """Open a sqlite database, converting it from a db file if needed."""
    if os.path.exists(sqlite_file):
        return openDatabase(sqlite_file)

    conn = sqlite3.Connection(sqlite_file)
    cur = conn.cursor()
    cur.executescript(SCHEMA2_SCRIPT)
    conn.commit()

    import anydbm

    try:
        db = anydbm.open(db_file, 'r')
    except anydbm.error:
        return conn

    try:
        # We handle all the sp| keys first, since other tables have
        # dependencies on Bridges.
        for k in db.keys():
            v = db[k]
            if k.startswith("sp|"):
                assert len(k) == 23
                cur.execute("INSERT INTO Bridges ( hex_key, distributor ) "
                            "VALUES (?, ?)", (toHex(k[3:]),v))
        # Now we handle the other key types.
        for k in db.keys():
            v = db[k]
            if k.startswith("fs|"):
                assert len(k) == 23
                cur.execute("UPDATE Bridges SET first_seen = ? "
                            "WHERE hex_key = ?", (v, toHex(k[3:])))
            elif k.startswith("ls|"):
                assert len(k) == 23
                cur.execute("UPDATE Bridges SET last_seen = ? "
                            "WHERE hex_key = ?", (v, toHex(k[3:])))
            #elif k.startswith("em|"):
            #    keys = list(toHex(i) for i in
            #        bridgedb.Bridges.chopString(v, bridgedb.Bridges.ID_LEN))
            #    cur.executemany("INSERT INTO EmailedBridges ( email, id ) "
            #                    "SELECT ?, id FROM Bridges WHERE hex_key = ?",
            #                    [(k[3:],i) for i in keys])
            elif k.startswith("sp|") or k.startswith("em|"):
                pass
            else:
                logging.warn("Unrecognized key %r", k)
    except:
        conn.rollback()
        conn.close()
        os.unlink(sqlite_file)
        raise

    conn.commit()
    return conn

_THE_DB = None

def setGlobalDB(db):
    global _THE_DB
    _THE_DB = db

def getDB():
    return _THE_DB

