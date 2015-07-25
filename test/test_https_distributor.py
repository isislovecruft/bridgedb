# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013-2015 Isis Lovecruft
#             (c) 2007-2015, The Tor Project, Inc.
#             (c) 2007-2015, all entities within the AUTHORS file
# :license: 3-clause BSD, see included LICENSE for information

"""Tests for :mod:`bridgedb.https.distributor`."""

from __future__ import print_function

import ipaddr
import logging
import random

from twisted.trial import unittest

from bridgedb.Bridges import BridgeRing
from bridgedb.Bridges import BridgeRingParameters
from bridgedb.filters import byIPv4
from bridgedb.filters import byIPv6
from bridgedb.https import distributor
from bridgedb.https.request import HTTPSBridgeRequest
from bridgedb.proxy import ProxySet

from .util import randomValidIPv4String
from .util import generateFakeBridges
from .https_helpers import DummyRequest

logging.disable(50)


BRIDGES = generateFakeBridges()


class HTTPSDistributorTests(unittest.TestCase):
    """Tests for :class:`HTTPSDistributor`."""

    def setUp(self):
        self.key = 'aQpeOFIj8q20s98awfoiq23rpOIjFaqpEWFoij1X'
        self.bridges = BRIDGES

    def tearDown(self):
        """Reset all bridge blocks in between test method runs."""
        for bridge in self.bridges:
            bridge._blockedIn = {}

    def coinFlip(self):
        return bool(random.getrandbits(1))

    def randomClientRequest(self):
        bridgeRequest = HTTPSBridgeRequest(addClientCountryCode=False)
        bridgeRequest.client = randomValidIPv4String()
        bridgeRequest.isValid(True)
        bridgeRequest.generateFilters()
        return bridgeRequest

    def randomClientRequestForNotBlockedIn(self, cc):
        httpRequest = DummyRequest([''])
        httpRequest.args.update({'unblocked': [cc]})
        bridgeRequest = self.randomClientRequest()
        bridgeRequest.withoutBlockInCountry(httpRequest)
        bridgeRequest.generateFilters()
        return bridgeRequest

    def test_HTTPSDistributor_init_with_proxies(self):
        """The HTTPSDistributor, when initialised with proxies, should add an
        extra hashring for proxy users.
        """
        dist = distributor.HTTPSDistributor(3, self.key, ProxySet(['1.1.1.1', '2.2.2.2']))
        self.assertIsNotNone(dist.proxies)
        self.assertGreater(dist.proxySubring, 0)
        self.assertEqual(dist.proxySubring, 4)
        self.assertEqual(dist.totalSubrings, 4)

    def test_HTTPSDistributor_bridgesPerResponse_120(self):
        dist = distributor.HTTPSDistributor(3, self.key)
        [dist.insert(bridge) for bridge in self.bridges[:120]]
        self.assertEqual(dist.bridgesPerResponse(), 3)

    def test_HTTPSDistributor_bridgesPerResponse_100(self):
        dist = distributor.HTTPSDistributor(3, self.key)
        [dist.hashring.insert(bridge) for bridge in self.bridges[:100]]
        self.assertEqual(dist.bridgesPerResponse(), 3)

    def test_HTTPSDistributor_bridgesPerResponse_50(self):
        dist = distributor.HTTPSDistributor(3, self.key)
        [dist.insert(bridge) for bridge in self.bridges[:60]]
        self.assertEqual(dist.bridgesPerResponse(), 2)

    def test_HTTPSDistributor_bridgesPerResponse_15(self):
        dist = distributor.HTTPSDistributor(3, self.key)
        [dist.insert(bridge) for bridge in self.bridges[:15]]
        self.assertEqual(dist.bridgesPerResponse(), 1)

    def test_HTTPSDistributor_bridgesPerResponse_100_max_5(self):
        dist = distributor.HTTPSDistributor(3, self.key)
        dist._bridgesPerResponseMax = 5
        [dist.insert(bridge) for bridge in self.bridges[:100]]
        self.assertEqual(dist.bridgesPerResponse(), 5)

    def test_HTTPSDistributor_getSubnet_usingProxy(self):
        """HTTPSDistributor.getSubnet(usingProxy=True) should return a proxy
        group number.
        """
        clientRequest = self.randomClientRequest()
        expectedGroup = (int(ipaddr.IPAddress(clientRequest.client)) % 4) + 1
        subnet = distributor.HTTPSDistributor.getSubnet(clientRequest.client, usingProxy=True)
        self.assertTrue(subnet.startswith('proxy-group-'))
        self.assertEqual(int(subnet[-1]), expectedGroup)

    def test_HTTPSDistributor_mapSubnetToSubring_usingProxy(self):
        """HTTPSDistributor.mapSubnetToSubring() when the client was using a
        proxy should map the client to the proxy subhashring.
        """
        dist = distributor.HTTPSDistributor(3, self.key, ProxySet(['1.1.1.1', '2.2.2.2']))
        subnet = 'proxy-group-3'
        subring = dist.mapSubnetToSubring(subnet, usingProxy=True)
        self.assertEqual(subring, dist.proxySubring)

    def test_HTTPSDistributor_mapSubnetToSubring_with_proxies(self):
        """HTTPSDistributor.mapSubnetToSubring() when the client wasn't using
        a proxy, but the distributor does have some known proxies and a
        proxySubring, should not map the client to the proxy subhashring.
        """
        dist = distributor.HTTPSDistributor(3, self.key, ProxySet(['1.1.1.1', '2.2.2.2']))
        # Note that if they were actually from a proxy, their subnet would be
        # something like "proxy-group-3".
        subnet = '15.1.0.0/16'
        subring = dist.mapSubnetToSubring(subnet, usingProxy=False)
        self.assertNotEqual(subring, dist.proxySubring)

    def test_HTTPSDistributor_prepopulateRings_with_proxies(self):
        """An HTTPSDistributor with proxies should prepopulate two extra
        subhashrings (one for each of HTTP-Proxy-IPv4 and HTTP-Proxy-IPv6).
        """
        dist = distributor.HTTPSDistributor(3, self.key, ProxySet(['1.1.1.1', '2.2.2.2']))
        [dist.insert(bridge) for bridge in self.bridges]
        dist.prepopulateRings()
        self.assertEqual(len(dist.hashring.filterRings), 8)

    def test_HTTPSDistributor_prepopulateRings_without_proxies(self):
        """An HTTPSDistributor without proxies should prepopulate
        totalSubrings * 2 subrings.
        """
        dist = distributor.HTTPSDistributor(3, self.key)
        [dist.insert(bridge) for bridge in self.bridges]
        dist.prepopulateRings()
        self.assertEqual(len(dist.hashring.filterRings), 6)

        ipv4subrings = []
        ipv6subrings = []

        for subringName, (filters, subring) in dist.hashring.filterRings.items():
            if 'IPv4' in subringName:
                ipv6subrings.append(subring)
            if 'IPv6' in subringName:
                ipv6subrings.append(subring)

        self.assertEqual(len(ipv4subrings), len(ipv6subrings))

    def test_HTTPSDistributor_getBridges_with_blocked_bridges(self):
        dist = distributor.HTTPSDistributor(1, self.key)
        bridges = self.bridges[:]

        for bridge in bridges:
            bridge.setBlockedIn('cn')

        [dist.insert(bridge) for bridge in bridges]

        for _ in range(5):
            clientRequest1 = self.randomClientRequestForNotBlockedIn('cn')
            b = dist.getBridges(clientRequest1, 1)
            self.assertEqual(len(b), 0)

            clientRequest2 = self.randomClientRequestForNotBlockedIn('ir')
            b = dist.getBridges(clientRequest2, 1)
            self.assertEqual(len(b), 3)

    def test_HTTPSDistributor_getBridges_with_some_blocked_bridges(self):
        dist = distributor.HTTPSDistributor(1, self.key)
        bridges = self.bridges[:]

        blockedCN = []
        blockedIR = []

        for bridge in bridges:
            if self.coinFlip():
                bridge.setBlockedIn('cn')
                blockedCN.append(bridge.fingerprint)

            if self.coinFlip():
                bridge.setBlockedIn('ir')
                blockedIR.append(bridge.fingerprint)

        [dist.insert(bridge) for bridge in bridges]

        for _ in range(5):
            clientRequest1 = self.randomClientRequestForNotBlockedIn('cn')
            bridges = dist.getBridges(clientRequest1, 1)
            for b in bridges:
                self.assertFalse(b.isBlockedIn('cn'))
                self.assertNotIn(b.fingerprint, blockedCN)
            # The client *should* have gotten some bridges still.
            self.assertGreater(len(bridges), 0)

            clientRequest2 = self.randomClientRequestForNotBlockedIn('ir')
            bridges = dist.getBridges(clientRequest2, 1)
            for b in bridges:
                self.assertFalse(b.isBlockedIn('ir'))
                self.assertNotIn(b.fingerprint, blockedIR)
            self.assertGreater(len(bridges), 0)

    def test_HTTPSDistributor_getBridges_with_varied_blocked_bridges(self):
        dist = distributor.HTTPSDistributor(1, self.key)
        bridges = self.bridges[:]

        for bridge in bridges:
            # Pretend that China blocks all vanilla bridges:
            bridge.setBlockedIn('cn', methodname='vanilla')
            # Pretend that China blocks all obfs2:
            bridge.setBlockedIn('cn', methodname='obfs2')
            # Pretend that China blocks some obfs3:
            if self.coinFlip():
                bridge.setBlockedIn('cn', methodname='obfs3')

        [dist.insert(bridge) for bridge in bridges]

        for i in xrange(5):
            bridgeRequest1 = self.randomClientRequestForNotBlockedIn('cn')
            bridgeRequest1.transports.append('obfs2')
            bridgeRequest1.generateFilters()
            # We shouldn't get any obfs2 bridges, since they're all blocked in
            # China:
            bridges = dist.getBridges(bridgeRequest1, "faketimestamp")
            self.assertEqual(len(bridges), 0)

            bridgeRequest2 = self.randomClientRequestForNotBlockedIn('cn')
            bridgeRequest2.transports.append('obfs3')
            bridgeRequest2.generateFilters()
            # We probably will get at least one bridge back!  It's pretty
            # unlikely to lose a coin flip 500 times in a row.
            bridges = dist.getBridges(bridgeRequest2, "faketimestamp")
            self.assertGreater(len(bridges), 0)

            bridgeRequest3 = self.randomClientRequestForNotBlockedIn('nl')
            bridgeRequest3.transports.append('obfs3')
            bridgeRequest3.generateFilters()
            # We should get bridges, since obfs3 isn't blocked in netherlands:
            bridges = dist.getBridges(bridgeRequest3, "faketimestamp")
            self.assertGreater(len(bridges), 0)

    def test_HTTPSDistributor_getBridges_with_proxy_and_nonproxy_users(self):
        """An HTTPSDistributor should give separate bridges to proxy users."""
        proxies = ProxySet(['.'.join(['1.1.1', str(x)]) for x in range(1, 256)])
        dist = distributor.HTTPSDistributor(3, self.key, proxies)
        [dist.insert(bridge) for bridge in self.bridges]

        for _ in range(10):
            bridgeRequest1 = self.randomClientRequest()
            bridgeRequest1.client = '.'.join(['1.1.1', str(random.randrange(1, 255))])

            bridgeRequest2 = self.randomClientRequest()
            bridgeRequest2.client = '.'.join(['9.9.9', str(random.randrange(1, 255))])

            n1 = dist.getBridges(bridgeRequest1, 1)
            n2 = dist.getBridges(bridgeRequest2, 1)

            self.assertGreater(len(n1), 0)
            self.assertGreater(len(n2), 0)

            for b in n1:
                self.assertNotIn(b, n2)
            for b in n2:
                self.assertNotIn(b, n1)

    def test_HTTPSDistributor_getBridges_same_bridges_to_same_client(self):
        """The same client asking for bridges from the HTTPSDistributor
        multiple times in a row should get the same bridges in response each
        time.
        """
        dist = distributor.HTTPSDistributor(3, self.key)
        [dist.insert(bridge) for bridge in self.bridges[:250]]

        bridgeRequest = self.randomClientRequest()
        responses = {}
        for i in range(5):
            responses[i] = dist.getBridges(bridgeRequest, 1)
        for i in range(4):
            self.assertItemsEqual(responses[i], responses[i+1])

    def test_HTTPSDistributor_getBridges_with_BridgeRingParameters(self):
       param = BridgeRingParameters(needPorts=[(443, 1)])
       dist = distributor.HTTPSDistributor(3, self.key, answerParameters=param)

       bridges = self.bridges[:32]
       for b in self.bridges:
           b.orPort = 443

       [dist.insert(bridge) for bridge in bridges]
       [dist.insert(bridge) for bridge in self.bridges[:250]]

       for _ in xrange(32):
           bridgeRequest = self.randomClientRequest()
           answer = dist.getBridges(bridgeRequest, 1)
           count = 0
           fingerprints = {}
           for bridge in answer:
               fingerprints[bridge.identity] = 1
               if bridge.orPort == 443:
                   count += 1
           self.assertEquals(len(fingerprints), len(answer))
           self.assertGreater(len(fingerprints), 0)
           self.assertTrue(count >= 1)

    def test_HTTPSDistributor_getBridges_ipv4_ipv6(self):
        """Asking for bridge addresses which are simultaneously IPv4 and IPv6
        (in that order) should return IPv4 bridges.
        """
        dist = distributor.HTTPSDistributor(1, self.key)
        [dist.insert(bridge) for bridge in self.bridges[:250]]

        bridgeRequest = self.randomClientRequest()
        bridgeRequest.withIPv4()
        bridgeRequest.filters.append(byIPv6)
        bridgeRequest.generateFilters()

        bridges = dist.getBridges(bridgeRequest, 1)
        self.assertEqual(len(bridges), 3)

        bridge = random.choice(bridges)
        bridgeLine = bridge.getBridgeLine(bridgeRequest)
        addrport, fingerprint = bridgeLine.split()
        address, port = addrport.rsplit(':', 1)
        address = address.strip('[]')
        self.assertIsInstance(ipaddr.IPAddress(address), ipaddr.IPv4Address)
        self.assertIsNotNone(byIPv4(random.choice(bridges)))

    def test_HTTPSDistributor_getBridges_ipv6_ipv4(self):
        """Asking for bridge addresses which are simultaneously IPv6 and IPv4
        (in that order) should return IPv6 bridges.
        """
        dist = distributor.HTTPSDistributor(1, self.key)
        [dist.insert(bridge) for bridge in self.bridges[:250]]

        bridgeRequest = self.randomClientRequest()
        bridgeRequest.withIPv6()
        bridgeRequest.generateFilters()
        bridgeRequest.filters.append(byIPv4)

        bridges = dist.getBridges(bridgeRequest, 1)
        self.assertEqual(len(bridges), 3)

        bridge = random.choice(bridges)
        bridgeLine = bridge.getBridgeLine(bridgeRequest)
        addrport, fingerprint = bridgeLine.split()
        address, port = addrport.rsplit(':', 1)
        address = address.strip('[]')
        self.assertIsInstance(ipaddr.IPAddress(address), ipaddr.IPv6Address)
        self.assertIsNotNone(byIPv6(random.choice(bridges)))

    def test_HTTPSDistributor_getBridges_ipv6(self):
        """A request for IPv6 bridges should return IPv6 bridges."""
        dist = distributor.HTTPSDistributor(3, self.key)
        [dist.insert(bridge) for bridge in self.bridges[:250]]

        for i in xrange(500):
            bridgeRequest = self.randomClientRequest()
            bridgeRequest.withIPv6()
            bridgeRequest.generateFilters()

            bridges = dist.getBridges(bridgeRequest, "faketimestamp")
            self.assertTrue(type(bridges) is list)
            self.assertGreater(len(bridges), 0)

            bridge = random.choice(bridges)
            bridgeLine = bridge.getBridgeLine(bridgeRequest)
            addrport, fingerprint = bridgeLine.split()
            address, port = addrport.rsplit(':', 1)
            address = address.strip('[]')
            self.assertIsInstance(ipaddr.IPAddress(address), ipaddr.IPv6Address)
            self.assertIsNotNone(byIPv6(random.choice(bridges)))

    def test_HTTPSDistributor_getBridges_ipv4(self):
        """A request for IPv4 bridges should return IPv4 bridges."""
        dist = distributor.HTTPSDistributor(1, self.key)
        [dist.insert(bridge) for bridge in self.bridges[:250]]

        for i in xrange(500):
            bridgeRequest = self.randomClientRequest()
            bridgeRequest.generateFilters()

            bridges = dist.getBridges(bridgeRequest, "faketimestamp")
            self.assertTrue(type(bridges) is list)
            self.assertGreater(len(bridges), 0)

            bridge = random.choice(bridges)
            bridgeLine = bridge.getBridgeLine(bridgeRequest)
            addrport, fingerprint = bridgeLine.split()
            address, port = addrport.rsplit(':', 1)
            self.assertIsInstance(ipaddr.IPAddress(address), ipaddr.IPv4Address)
            self.assertIsNotNone(byIPv4(random.choice(bridges)))
