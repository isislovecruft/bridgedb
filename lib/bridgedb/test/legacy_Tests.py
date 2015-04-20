# BridgeDB by Nick Mathewson.
# Copyright (c) 2007-2009, The Tor Project, Inc.
# See LICENSE for licensing information

"""These are legacy integration and unittests which historically lived at
``lib/bridgedb/Tests.py``. They have been moved here to keep the test code
separate from the production codebase.
"""

from __future__ import print_function

import os
import random
import tempfile
import unittest
import warnings
import time
from datetime import datetime

import bridgedb.Bridges
import bridgedb.Main
import bridgedb.Dist
import bridgedb.schedule
import bridgedb.Storage
import re
import ipaddr

from bridgedb.Filters import filterBridgesByIP4
from bridgedb.Filters import filterBridgesByIP6
from bridgedb.Filters import filterBridgesByTransport
from bridgedb.Filters import filterBridgesByNotBlockedIn

from bridgedb.Stability import BridgeHistory

from bridgedb.parse import addr
from bridgedb.test import deprecated_networkstatus as networkstatus
from bridgedb.test.util import bracketIPv6
from bridgedb.test.util import randomIP
from bridgedb.test.util import randomIPv4
from bridgedb.test.util import randomIPv6
from bridgedb.test.util import randomIPString
from bridgedb.test.util import randomIPv4String
from bridgedb.test.util import randomIPv6String

from math import log


def suppressWarnings():
    warnings.filterwarnings('ignore', '.*tmpnam.*')

def randomPort():
    return random.randint(1,65535)

def randomPortSpec():
    """
    returns a random list of ports
    """
    ports = []
    for i in range(0,24):
        ports.append(random.randint(1,65535))
    ports.sort(reverse=True)

    portspec = ""
    for i in range(0,16):
        portspec += "%d," % random.choice(ports)
    portspec = portspec.rstrip(',') #remove trailing ,
    return portspec

def fakeBridge(orport=8080, running=True, stable=True, or_addresses=False,
        transports=False):
    nn = "bridge-%s"%random.randrange(0,1000000)
    ip = ipaddr.IPAddress(randomIPv4())
    fp = "".join([random.choice("0123456789ABCDEF") for _ in xrange(40)])
    b = bridgedb.Bridges.Bridge(nn,ip,orport,fingerprint=fp)
    b.setStatus(running, stable)

    oraddrs = []
    if or_addresses:
        for i in xrange(8):
            # Only add or_addresses if they are valid. Otherwise, the test
            # will randomly fail if an invalid address is chosen:
            address = randomIPv4String()
            portlist = addr.PortList(randomPortSpec())
            if addr.isValidIP(address):
                oraddrs.append((address, portlist,))

    for address, portlist in oraddrs:
        networkstatus.parseALine("{0}:{1}".format(address, portlist))
        try:
            portlist.add(b.or_addresses[address])
        except KeyError:
            pass
        finally:
            b.or_addresses[address] = portlist

    if transports:
        for i in xrange(0,8):
            b.transports.append(bridgedb.Bridges.PluggableTransport(b,
                random.choice(["obfs", "obfs2", "pt1"]),
                randomIP(), randomPort()))
    return b

def fakeBridge6(orport=8080, running=True, stable=True, or_addresses=False,
        transports=False):
    nn = "bridge-%s"%random.randrange(0,1000000)
    ip = ipaddr.IPAddress(randomIPv6())
    fp = "".join([random.choice("0123456789ABCDEF") for _ in xrange(40)])
    b = bridgedb.Bridges.Bridge(nn,ip,orport,fingerprint=fp)
    b.setStatus(running, stable)

    oraddrs = []
    if or_addresses:
        for i in xrange(8):
            # Only add or_addresses if they are valid. Otherwise, the test
            # will randomly fail if an invalid address is chosen:
            address = randomIPv6()
            portlist = addr.PortList(randomPortSpec())
            if addr.isValidIP(address):
                address = bracketIPv6(address)
                oraddrs.append((address, portlist,))

    for address, portlist in oraddrs:
        networkstatus.parseALine("{0}:{1}".format(address, portlist))
        try:
            portlist.add(b.or_addresses[address])
        except KeyError:
            pass
        finally:
            b.or_addresses[address] = portlist

            try:
                portlist.add(b.or_addresses[address])
            except KeyError:
                pass
            finally:
                b.or_addresses[address] = portlist

    if transports:
        for i in xrange(0,8):
            b.transports.append(bridgedb.Bridges.PluggableTransport(b,
                random.choice(["obfs", "obfs2", "pt1"]),
                randomIP(), randomPort()))

    return b

simpleDesc = "router Unnamed %s %s 0 9030\n"\
"opt fingerprint DEAD BEEF F00F DEAD BEEF F00F DEAD BEEF F00F DEAD\n"\
"opt @purpose bridge\n"
orAddress = "or-address %s:%s\n"


class RhymesWith255ProxySet:
    def __contains__(self, ip):
        return ip.endswith(".255")

class EmailBridgeDistTests(unittest.TestCase):
    def setUp(self):
        self.fd, self.fname = tempfile.mkstemp()
        self.db = bridgedb.Storage.Database(self.fname)
        bridgedb.Storage.setDB(self.db)
        self.cur = self.db._conn.cursor()

    def tearDown(self):
        self.db.close()
        os.close(self.fd)
        os.unlink(self.fname)

    def testEmailRateLimit(self):
        db = self.db
        EMAIL_DOMAIN_MAP = {'example.com':'example.com'}
        d = bridgedb.Dist.EmailBasedDistributor(
                "Foo",
                {'example.com': 'example.com',
                    'dkim.example.com': 'dkim.example.com'},
                {'example.com': [], 'dkim.example.com': ['dkim']})
        for _ in xrange(256):
            d.insert(fakeBridge())
        d.getBridges('abc@example.com', 1)
        self.assertRaises(bridgedb.Dist.TooSoonEmail,
                d.getBridges, 'abc@example.com', 1)
        self.assertRaises(bridgedb.Dist.IgnoreEmail,
                d.getBridges, 'abc@example.com', 1)

    def testUnsupportedDomain(self):
        db = self.db
        self.assertRaises(bridgedb.parse.addr.UnsupportedDomain,
                          bridgedb.parse.addr.normalizeEmail,
                          'bad@email.com',
                          {'example.com':'example.com'},
                          {'example.com':[]})

class IPBridgeDistTests(unittest.TestCase):

    def testDistWithFilterIP4(self):
        d = bridgedb.Dist.HTTPSDistributor(3, "Foo")
        for _ in xrange(250):
            d.insert(fakeBridge6(or_addresses=True))
            d.insert(fakeBridge(or_addresses=True))

        for i in xrange(500):
            bridges = d.getBridges(randomIPv4String(),
                                   "faketimestamp",
                                   bridgeFilterRules=[filterBridgesByIP4])
            bridge = random.choice(bridges)
            bridge_line = bridge.getConfigLine(addressClass=ipaddr.IPv4Address)
            address, portlist = networkstatus.parseALine(bridge_line)
            assert type(ipaddr.IPAddress(address)) is ipaddr.IPv4Address
            assert filterBridgesByIP4(random.choice(bridges))

    def testDistWithFilterBoth(self):
        d = bridgedb.Dist.HTTPSDistributor(3, "Foo")
        for _ in xrange(250):
            d.insert(fakeBridge6(or_addresses=True))
            d.insert(fakeBridge(or_addresses=True))

        for i in xrange(50):
            bridges = d.getBridges(randomIPv4String(),
                                   "faketimestamp",
                                   bridgeFilterRules=[
                                       filterBridgesByIP4,
                                       filterBridgesByIP6])
            if bridges:
                t = bridges.pop()
                assert filterBridgesByIP4(t)
                assert filterBridgesByIP6(t)
                address, portlist = networkstatus.parseALine(
                    t.getConfigLine(addressClass=ipaddr.IPv4Address))
                assert type(address) is ipaddr.IPv4Address
                address, portlist = networkstatus.parseALine(
                    t.getConfigLine(addressClass=ipaddr.IPv6Address))
                assert type(address) is ipaddr.IPv6Address

    def testDistWithFilterBlockedCountriesAdvanced(self):
        d = bridgedb.Dist.HTTPSDistributor(3, "Foo")
        for _ in xrange(250):
            d.insert(fakeBridge6(or_addresses=True, transports=True))
            d.insert(fakeBridge(or_addresses=True, transports=True))

        for b in d.hashring.bridges:
            # china blocks some transports
            for pt in b.transports:
                if random.choice(xrange(2)) > 0:
                    key = "%s:%s" % (pt.address, pt.port)
                    b.blockingCountries[key] = set(['cn'])
            for address, portlist in b.or_addresses.items():
                # china blocks some transports
                for port in portlist:
                    if random.choice(xrange(2)) > 0:
                        key = "%s:%s" % (address, port)
                        b.blockingCountries[key] = set(['cn'])
            key = "%s:%s" % (b.ip, b.orport)
            b.blockingCountries[key] = set(['cn'])

        # we probably will get at least one bridge back!
        # it's pretty unlikely to lose a coin flip 250 times in a row
        for i in xrange(5):
            b = d.getBridges(randomIPString(), "x",
                    bridgeFilterRules=[
                        filterBridgesByNotBlockedIn("cn"),
                        filterBridgesByTransport('obfs2'),
                        ])
            try: assert len(b) > 0
            except AssertionError:
                print("epic fail")
            b = d.getBridges(randomIPString(), "x", bridgeFilterRules=[
                filterBridgesByNotBlockedIn("us")])
            assert len(b) > 0


class SQLStorageTests(unittest.TestCase):
    def setUp(self):
        self.fd, self.fname = tempfile.mkstemp()
        self.db = bridgedb.Storage.Database(self.fname)
        self.cur = self.db._conn.cursor()

    def tearDown(self):
        self.db.close()
        os.close(self.fd)
        os.unlink(self.fname)

    def assertCloseTo(self, a, b, delta=60):
        self.assertTrue(abs(a-b) <= delta)

    def testBridgeStorage(self):
        db = self.db
        B = bridgedb.Bridges.Bridge
        t = time.time()
        cur = self.cur

        k1 = "AAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBB"
        k2 = "ABABABABABABABABABABABABABABABABABABABAB"
        k3 = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
        b1 = B("serv1", "1.2.3.4", 999, fingerprint=k1)
        b1_v2 = B("serv1", "1.2.3.5", 9099, fingerprint=k1)
        b2 = B("serv2", "2.3.4.5", 9990, fingerprint=k2)
        b3 = B("serv3", "2.3.4.6", 9008, fingerprint=k3)
        validRings = ["ring1", "ring2", "ring3"]

        r = db.insertBridgeAndGetRing(b1, "ring1", t, validRings)
        self.assertEquals(r, "ring1")
        r = db.insertBridgeAndGetRing(b1, "ring10", t+500, validRings)
        self.assertEquals(r, "ring1")

        cur.execute("SELECT distributor, address, or_port, first_seen, "
                    "last_seen FROM Bridges WHERE hex_key = ?", (k1,))
        v = cur.fetchone()
        self.assertEquals(v,
                          ("ring1", "1.2.3.4", 999,
                           bridgedb.Storage.timeToStr(t),
                           bridgedb.Storage.timeToStr(t+500)))

        r = db.insertBridgeAndGetRing(b1_v2, "ring99", t+800, validRings)
        self.assertEquals(r, "ring1")
        cur.execute("SELECT distributor, address, or_port, first_seen, "
                    "last_seen FROM Bridges WHERE hex_key = ?", (k1,))
        v = cur.fetchone()
        self.assertEquals(v,
                          ("ring1", "1.2.3.5", 9099,
                           bridgedb.Storage.timeToStr(t),
                           bridgedb.Storage.timeToStr(t+800)))

        db.insertBridgeAndGetRing(b2, "ring2", t, validRings)
        db.insertBridgeAndGetRing(b3, "ring3", t, validRings)

        cur.execute("SELECT COUNT(distributor) FROM Bridges")
        v = cur.fetchone()
        self.assertEquals(v, (3,))

        r = db.getEmailTime("abc@example.com")
        self.assertEquals(r, None)
        db.setEmailTime("abc@example.com", t)
        db.setEmailTime("def@example.com", t+1000)
        r = db.getEmailTime("abc@example.com")
        self.assertCloseTo(r, t)
        r = db.getEmailTime("def@example.com")
        self.assertCloseTo(r, t+1000)
        r = db.getEmailTime("ghi@example.com")
        self.assertEquals(r, None)

        db.cleanEmailedBridges(t+200)
        db.setEmailTime("def@example.com", t+5000)
        r = db.getEmailTime("abc@example.com")
        self.assertEquals(r, None)
        r = db.getEmailTime("def@example.com")
        self.assertCloseTo(r, t+5000)
        cur.execute("SELECT * FROM EmailedBridges")
        self.assertEquals(len(cur.fetchall()), 1)

        self.assertEquals(db.getWarnedEmail("def@example.com"), False)
        db.setWarnedEmail("def@example.com")
        self.assertEquals(db.getWarnedEmail("def@example.com"), True)
        db.setWarnedEmail("def@example.com", False)
        self.assertEquals(db.getWarnedEmail("def@example.com"), False)

        db.setWarnedEmail("def@example.com")
        self.assertEquals(db.getWarnedEmail("def@example.com"), True)
        db.cleanWarnedEmails(t+200)
        self.assertEquals(db.getWarnedEmail("def@example.com"), False)


class BridgeStabilityTests(unittest.TestCase):
    def setUp(self):
        self.fd, self.fname = tempfile.mkstemp()
        self.db = bridgedb.Storage.Database(self.fname)
        bridgedb.Storage.setDB(self.db)
        self.cur = self.db._conn.cursor()

    def tearDown(self):
        self.db.close()
        os.close(self.fd)
        os.unlink(self.fname)

    def testAddOrUpdateSingleBridgeHistory(self):
        db = self.db
        b = fakeBridge()
        timestamp = time.time()
        bhe = bridgedb.Stability.addOrUpdateBridgeHistory(b, timestamp)
        assert isinstance(bhe, BridgeHistory)
        assert isinstance(db.getBridgeHistory(b.fingerprint), BridgeHistory)
        assert len([y for y in db.getAllBridgeHistory()]) == 1

    def testDeletingSingleBridgeHistory(self):
        db = self.db
        b = fakeBridge()
        timestamp = time.time()
        bhe = bridgedb.Stability.addOrUpdateBridgeHistory(b, timestamp)
        assert isinstance(bhe, BridgeHistory)
        assert isinstance(db.getBridgeHistory(b.fingerprint), BridgeHistory)
        db.delBridgeHistory(b.fingerprint)
        assert db.getBridgeHistory(b.fingerprint) is None
        assert len([y for y in db.getAllBridgeHistory()]) == 0

    def testTOSA(self):
        db = self.db
        b = random.choice([fakeBridge,fakeBridge6])()
        def timestampSeries(x):
            for i in xrange(61):
                yield (i+1)*60*30 + x # 30 minute intervals
        now = time.time()
        time_on_address = long(60*30*60) # 30 hours
        downtime = 60*60*random.randint(0,4) # random hours of downtime

        for t in timestampSeries(now):
            bridgedb.Stability.addOrUpdateBridgeHistory(b,t)
        assert db.getBridgeHistory(b.fingerprint).tosa == time_on_address

        b.orport += 1

        for t in timestampSeries(now + time_on_address + downtime):
            bhe = bridgedb.Stability.addOrUpdateBridgeHistory(b,t)
        assert db.getBridgeHistory(b.fingerprint).tosa == time_on_address + downtime

    def testLastSeenWithDifferentAddressAndPort(self):
        db = self.db
        for i in xrange(10):
            num_desc = 30
            time_start = time.time()
            ts = [ 60*30*(i+1) + time_start for i in xrange(num_desc) ]
            b = random.choice([fakeBridge(), fakeBridge6()])
            [ bridgedb.Stability.addOrUpdateBridgeHistory(b, t) for t in ts ]

            # change the port
            b.orport = b.orport+1
            last_seen = ts[-1]
            ts = [ 60*30*(i+1) + last_seen for i in xrange(num_desc) ]
            [ bridgedb.Stability.addOrUpdateBridgeHistory(b, t) for t in ts ]
            b = db.getBridgeHistory(b.fingerprint)
            assert b.tosa == ts[-1] - last_seen
            assert (long(last_seen*1000) == b.lastSeenWithDifferentAddressAndPort)
            assert (long(ts[-1]*1000) == b.lastSeenWithThisAddressAndPort)

    def testFamiliar(self):
        # create some bridges
        # XXX: slow
        num_bridges = 10
        num_desc = 4*48 # 30m intervals, 48 per day
        time_start = time.time()
        bridges = [ fakeBridge() for x in xrange(num_bridges) ]
        t = time.time()
        ts = [ (i+1)*60*30+t for i in xrange(num_bridges) ]
        for b in bridges:
            time_series = [ 60*30*(i+1) + time_start for i in xrange(num_desc) ]
            [ bridgedb.Stability.addOrUpdateBridgeHistory(b, i) for i in time_series ]
        assert None not in bridges
        # +1 to avoid rounding errors
        assert bridges[-(num_bridges/8 + 1)].familiar == True

    def testDiscountAndPruneBridgeHistory(self):
        """ Test pruning of old Bridge History """
        if os.environ.get('TRAVIS'):
            self.skipTest("Hangs on Travis-CI.")

        db = self.db

        # make a bunch of bridges
        num_bridges = 20
        time_start = time.time()
        bridges = [random.choice([fakeBridge, fakeBridge6])()
                   for i in xrange(num_bridges)]

        # run some of the bridges for the full time series
        running = bridges[:num_bridges/2]
        # and some that are not
        expired = bridges[num_bridges/2:]

        for b in running: assert b not in expired

        # Solving:
        # 1 discount event per 12 hours, 24 descriptors 30m apart
        num_successful = random.randint(2,60)
        # figure out how many intervals it will take for weightedUptime to
        # decay to < 1
        num_desc = int(30*log(1/float(num_successful*30*60))/(-0.05))
        timeseries = [ 60*30*(i+1) + time_start for i in xrange(num_desc) ]

        for i in timeseries:
            for b in running:
                bridgedb.Stability.addOrUpdateBridgeHistory(b, i)

            if num_successful > 0:
                for b in expired:
                    bridgedb.Stability.addOrUpdateBridgeHistory(b, i)
            num_successful -= 1

        # now we expect to see the bridge has been removed from history
        for bridge in expired:
            b = db.getBridgeHistory(bridge.fingerprint)
            assert b is None
        # and make sure none of the others have
        for bridge in running:
            b = db.getBridgeHistory(bridge.fingerprint)
            assert b is not None

def testSuite():
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()

    for klass in [IPBridgeDistTests, SQLStorageTests, EmailBridgeDistTests,
                  BridgeStabilityTests]:
        suite.addTest(loader.loadTestsFromTestCase(klass))
    return suite

def main():
    suppressWarnings()

    unittest.TextTestRunner(verbosity=1).run(testSuite())
