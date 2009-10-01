# BridgeDB by Nick Mathewson.
# Copyright (c) 2007-2009, The Tor Project, Inc.
# See LICENSE for licensing information

import doctest
import os
import random
import sqlite3
import tempfile
import unittest
import warnings
import time

import bridgedb.Bridges
import bridgedb.Main
import bridgedb.Dist
import bridgedb.Time
import bridgedb.Storage

def suppressWarnings():
    warnings.filterwarnings('ignore', '.*tmpnam.*')

def randomIP():
    return ".".join([str(random.randrange(1,256)) for _ in xrange(4)])

def fakeBridge(orport=8080):
    nn = "bridge-%s"%random.randrange(0,1000000)
    ip = randomIP()
    fp = "".join([random.choice("0123456789ABCDEF") for _ in xrange(40)])
    return bridgedb.Bridges.Bridge(nn,ip,orport,fingerprint=fp)

class RhymesWith255Category:
    def contains(self, ip):
        return ip.endswith(".255")

class IPBridgeDistTests(unittest.TestCase):
    def dumbAreaMapper(self, ip):
        return ip
    def testBasicDist(self):
        d = bridgedb.Dist.IPBasedDistributor(self.dumbAreaMapper, 3, "Foo")
        for _ in xrange(256):
            d.insert(fakeBridge())
        n = d.getBridgesForIP("1.2.3.4", "x", 2)
        n2 = d.getBridgesForIP("1.2.3.4", "x", 2)
        self.assertEquals(n, n2)

    def testDistWithCategories(self):
        d = bridgedb.Dist.IPBasedDistributor(self.dumbAreaMapper, 3, "Foo",
                                             [RhymesWith255Category()])
        assert len(d.categoryRings) == 1
        rhymesWith255Ring = d.categoryRings[0]
        for _ in xrange(256):
            d.insert(fakeBridge())
        # Make sure this IP doesn't get any rhymes-with-255 bridges
        n = d.getBridgesForIP("1.2.3.4", "x", 10)
        for b in n:
            self.assertFalse(b.getID() in rhymesWith255Ring.bridgesByID)

        # Make sure these IPs all get rhymes-with-255 bridges
        for ip in ("6.7.8.255", "10.10.10.255"):
            n = d.getBridgesForIP("1.2.3.255", "xyz", 10)
            for b in n:
                self.assertTrue(b.getID() in rhymesWith255Ring.bridgesByID)

    def testDistWithPortRestrictions(self):
        param = bridgedb.Bridges.BridgeRingParameters(needPorts=[(443, 1)])
        d = bridgedb.Dist.IPBasedDistributor(self.dumbAreaMapper, 3, "Baz",
                                             answerParameters=param)
        for _ in xrange(32):
            d.insert(fakeBridge(443))
        for _ in range(256):
            d.insert(fakeBridge())
        for _ in xrange(32):
            i = randomIP()
            n = d.getBridgesForIP(i, "x", 5)
            count = 0
            fps = {}
            for b in n:
                fps[b.getID()] = 1
                if b.orport == 443:
                    count += 1
            self.assertEquals(len(fps), len(n))
            self.assertEquals(len(fps), 5)
            self.assertTrue(count >= 1)

class DictStorageTests(unittest.TestCase):
    def setUp(self):
        self.fd, self.fname = tempfile.mkstemp()
        self.conn = sqlite3.Connection(self.fname)

    def tearDown(self):
        self.conn.close()
        os.close(self.fd)
        os.unlink(self.fname)

    def testSimpleDict(self):
        self.conn.execute("CREATE TABLE A ( X PRIMARY KEY, Y )")
        d = bridgedb.Storage.SqliteDict(self.conn, self.conn.cursor(),
                                        "A", (), (), "X", "Y")

        self.basictests(d)

    def testComplexDict(self):
        self.conn.execute("CREATE TABLE B ( X, Y, Z, "
                          "CONSTRAINT B_PK PRIMARY KEY (X,Y) )")
        d = bridgedb.Storage.SqliteDict(self.conn, self.conn.cursor(),
                                        "B", ("X",), ("x1",), "Y", "Z")
        d2 = bridgedb.Storage.SqliteDict(self.conn, self.conn.cursor(),
                                         "B", ("X",), ("x2",), "Y", "Z")
        self.basictests(d)
        self.basictests(d2)

    def basictests(self, d):
        d["hello"] = "goodbye"
        d["hola"] = "adios"
        self.assertEquals(d["hola"], "adios")
        d["hola"] = "hasta luego"
        self.assertEquals(d["hola"], "hasta luego")
        self.assertEquals(sorted(d.keys()), [u"hello", u"hola"])
        self.assertRaises(KeyError, d.__getitem__, "buongiorno")
        self.assertEquals(d.get("buongiorno", "ciao"), "ciao")
        self.conn.commit()
        d["buongiorno"] = "ciao"
        del d['hola']
        self.assertRaises(KeyError, d.__getitem__, "hola")
        self.conn.rollback()
        self.assertEquals(d["hola"], "hasta luego")
        self.assertEquals(d.setdefault("hola","bye"), "hasta luego")
        self.assertEquals(d.setdefault("yo","bye"), "bye")
        self.assertEquals(d['yo'], "bye")

class SQLStorageTests(unittest.TestCase):
    def setUp(self):
        self.fd, self.fname = tempfile.mkstemp()
        self.db = bridgedb.Storage.Database(self.fname)
        self.cur = self.db._conn.cursor()

    def tearDown(self):
        self.db.close()
        os.close(self.fd)
        os.unlink(self.fname)

    def testBridgeStorage(self):
        db = self.db
        B = bridgedb.Bridges.Bridge
        t = time.time()
        cur = self.cur

        k1 = "aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbb"
        k2 = "abababababababababababababababababababab"
        k3 = "cccccccccccccccccccccccccccccccccccccccc"
        b1 = B("serv1", "1.2.3.4", 999, fingerprint=k1)
        b1_v2 = B("serv1", "1.2.3.5", 9099, fingerprint=k1)
        b2 = B("serv2", "2.3.4.5", 9990, fingerprint=k2)
        b3 = B("serv3", "2.3.4.6", 9008, fingerprint=k3)

        r = db.insertBridgeAndGetRing(b1, "ring1", t)
        self.assertEquals(r, "ring1")
        r = db.insertBridgeAndGetRing(b1, "ring10", t+500)
        self.assertEquals(r, "ring1")

        cur.execute("SELECT distributor, address, or_port, first_seen, "
                    "last_seen FROM Bridges WHERE hex_key = ?", (k1,))
        v = cur.fetchone()
        self.assertEquals(v,
                          ("ring1", "1.2.3.4", 999,
                           bridgedb.Storage.timeToStr(t),
                           bridgedb.Storage.timeToStr(t+500)))

        r = db.insertBridgeAndGetRing(b1_v2, "ring99", t+800)
        self.assertEquals(r, "ring1")
        cur.execute("SELECT distributor, address, or_port, first_seen, "
                    "last_seen FROM Bridges WHERE hex_key = ?", (k1,))
        v = cur.fetchone()
        self.assertEquals(v,
                          ("ring1", "1.2.3.5", 9099,
                           bridgedb.Storage.timeToStr(t),
                           bridgedb.Storage.timeToStr(t+800)))

        db.insertBridgeAndGetRing(b2, "ring2", t)
        db.insertBridgeAndGetRing(b3, "ring3", t)

        cur.execute("SELECT COUNT(distributor) FROM Bridges")
        v = cur.fetchone()
        self.assertEquals(v, (3,))

        r = db.getEmailedBridges("abc@example.com")
        self.assertEquals(r, [])
        db.addEmailedBridges("abc@example.com", t, [k1,k2])
        db.addEmailedBridges("def@example.com", t+1000, [k2,k3])
        r = db.getEmailedBridges("abc@example.com")
        self.assertEquals(sorted(r), sorted([k1,k2]))
        r = db.getEmailedBridges("def@example.com")
        self.assertEquals(sorted(r), sorted([k2,k3]))
        r = db.getEmailedBridges("ghi@example.com")
        self.assertEquals(r, [])

def testSuite():
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()

    for klass in [ IPBridgeDistTests, DictStorageTests, SQLStorageTests ]:
        suite.addTest(loader.loadTestsFromTestCase(klass))

    for module in [ bridgedb.Bridges,
                    bridgedb.Main,
                    bridgedb.Dist,
                    bridgedb.Time ]:
        suite.addTest(doctest.DocTestSuite(module))

    return suite

def main():
    suppressWarnings()

    unittest.TextTestRunner(verbosity=1).run(testSuite())



