# BridgeDB by Nick Mathewson.
# Copyright (c) 2007, The Tor Project, Inc.
# See LICENSE for licensing information

import doctest
import unittest
import warnings
import random

import bridgedb.Bridges
import bridgedb.Main
import bridgedb.Dist
import bridgedb.Time

def suppressWarnings():
    warnings.filterwarnings('ignore', '.*tmpnam.*')

class TestCase0(unittest.TestCase):
    def testFooIsFooish(self):
        self.assert_(True)

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

def testSuite():
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()

    for klass in [ TestCase0, IPBridgeDistTests ]:
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



