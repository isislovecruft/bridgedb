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

"""Tests for :mod:`bridgedb.Dist`."""

from __future__ import print_function

import hashlib
import ipaddr
import random

from twisted.trial import unittest

from bridgedb import Dist
from bridgedb.bridges import Bridge
from bridgedb.bridges import PluggableTransport
from bridgedb.Bridges import BridgeRing
from bridgedb.Filters import filterBridgesByNotBlockedIn
from bridgedb.https.request import HTTPSBridgeRequest
from bridgedb.proxy import ProxySet
from bridgedb.test.util import randomHighPort
from bridgedb.test.util import randomValidIPv4String
from bridgedb.test.util import randomValidIPv6
from bridgedb.test.https_helpers import DummyRequest


def _generateFakeBridges(n=500):
    bridges = []

    for i in range(n):
        addr = randomValidIPv4String()
        nick = 'bridge-%d' % i
        port = randomHighPort()
        # Real tor currently only supports one extra ORAddress, and it can
        # only be IPv6.
        addrs = [(randomValidIPv6(), randomHighPort(), 6)]
        fpr = "".join(random.choice('abcdef0123456789') for _ in xrange(40))

        # We only support the ones without PT args, because they're easier to fake.
        supported = ["obfs2", "obfs3", "fte"]
        transports = []
        for j, method in zip(range(1, len(supported) + 1), supported):
            pt = PluggableTransport(fpr, method, addr, port - j, {})
            transports.append(pt)

        bridge = Bridge(nick, addr, port, fpr, or_addresses=addrs)
        bridge.flags.update("Running Stable")
        bridge.transports = transports
        bridges.append(bridge)

    return bridges


BRIDGES = _generateFakeBridges()


class HTTPSDistributorTests(unittest.TestCase):
    """Tests for :class:`HTTPSDistributor`."""

    def setUp(self):
        self.key = 'aQpeOFIj8q20s98awfoiq23rpOIjFaqpEWFoij1X'
        self.bridges = BRIDGES

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
        dist = Dist.HTTPSDistributor(3, self.key, ProxySet(['1.1.1.1', '2.2.2.2']))
        self.assertIsNotNone(dist.proxies)
        self.assertGreater(dist.proxySubring, 0)
        self.assertEqual(dist.proxySubring, 4)
        self.assertEqual(dist.totalSubrings, 4)

    def test_HTTPSDistributor_bridgesPerResponse_120(self):
        dist = Dist.HTTPSDistributor(3, self.key)
        [dist.insert(bridge) for bridge in self.bridges[:120]]
        self.assertEqual(dist.bridgesPerResponse(), 3)

    def test_HTTPSDistributor_bridgesPerResponse_100(self):
        dist = Dist.HTTPSDistributor(3, self.key)
        [dist.hashring.insert(bridge) for bridge in self.bridges[:100]]
        self.assertEqual(dist.bridgesPerResponse(), 3)

    def test_HTTPSDistributor_bridgesPerResponse_50(self):
        dist = Dist.HTTPSDistributor(3, self.key)
        [dist.insert(bridge) for bridge in self.bridges[:60]]
        self.assertEqual(dist.bridgesPerResponse(), 2)

    def test_HTTPSDistributor_bridgesPerResponse_15(self):
        dist = Dist.HTTPSDistributor(3, self.key)
        [dist.insert(bridge) for bridge in self.bridges[:15]]
        self.assertEqual(dist.bridgesPerResponse(), 1)

    def test_HTTPSDistributor_bridgesPerResponse_100_max_5(self):
        dist = Dist.HTTPSDistributor(3, self.key)
        dist._bridgesPerResponseMax = 5
        [dist.insert(bridge) for bridge in self.bridges[:100]]
        self.assertEqual(dist.bridgesPerResponse(), 5)

    def test_HTTPSDistributor_getSubnet_usingProxy(self):
        """HTTPSDistributor.getSubnet(usingProxy=True) should return a proxy
        group number.
        """
        clientRequest = self.randomClientRequest()
        expectedGroup = (int(ipaddr.IPAddress(clientRequest.client)) % 4) + 1
        subnet = Dist.HTTPSDistributor.getSubnet(clientRequest.client, usingProxy=True)
        self.assertTrue(subnet.startswith('proxy-group-'))
        self.assertEqual(int(subnet[-1]), expectedGroup)

    def test_HTTPSDistributor_mapSubnetToSubring_usingProxy(self):
        """HTTPSDistributor.mapSubnetToSubring() when the client was using a
        proxy should map the client to the proxy subhashring.
        """
        dist = Dist.HTTPSDistributor(3, self.key, ProxySet(['1.1.1.1', '2.2.2.2']))
        subnet = 'proxy-group-3'
        subring = dist.mapSubnetToSubring(subnet, usingProxy=True)
        self.assertEqual(subring, dist.proxySubring)

    def test_HTTPSDistributor_mapSubnetToSubring_with_proxies(self):
        """HTTPSDistributor.mapSubnetToSubring() when the client wasn't using
        a proxy, but the distributor does have some known proxies and a
        proxySubring, should not map the client to the proxy subhashring.
        """
        dist = Dist.HTTPSDistributor(3, self.key, ProxySet(['1.1.1.1', '2.2.2.2']))
        # Note that if they were actually from a proxy, their subnet would be
        # something like "proxy-group-3".
        subnet = '15.1.0.0/16'
        subring = dist.mapSubnetToSubring(subnet, usingProxy=False)
        self.assertNotEqual(subring, dist.proxySubring)

    def test_HTTPSDistributor_prepopulateRings_with_proxies(self):
        """An HTTPSDistributor with proxies should prepopulate two extra
        subhashrings (one for each of HTTP-Proxy-IPv4 and HTTP-Proxy-IPv6).
        """
        dist = Dist.HTTPSDistributor(3, self.key, ProxySet(['1.1.1.1', '2.2.2.2']))
        [dist.insert(bridge) for bridge in self.bridges]
        dist.prepopulateRings()
        self.assertEqual(len(dist.hashring.filterRings), 8)

    def test_HTTPSDistributor_prepopulateRings_without_proxies(self):
        """An HTTPSDistributor without proxies should prepopulate
        totalSubrings * 2 subrings.
        """
        dist = Dist.HTTPSDistributor(3, self.key)
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

    def test_HTTPSDistributor_with_blocked_bridges(self):
        dist = Dist.HTTPSDistributor(3, self.key)
        [dist.insert(bridge) for bridge in self.bridges]

        for bridge in dist.hashring.bridges:
            bridge.setBlockedIn('cn')

        for _ in range(5):
            clientRequest1 = self.randomClientRequestForNotBlockedIn('cn')
            b = dist.getBridges(clientRequest1, 1)
            self.assertEqual(len(b), 0)

            clientRequest2 = self.randomClientRequestForNotBlockedIn('ir')
            b = dist.getBridges(clientRequest2, 1)
            self.assertEqual(len(b), 3)

    def test_HTTPSDistributor_with_some_blocked_bridges(self):
        dist = Dist.HTTPSDistributor(3, self.key)
        [dist.insert(bridge) for bridge in self.bridges]

        blockedCN = []
        blockedIR = []

        for bridge in dist.hashring.bridges:
            if self.coinFlip():
                bridge.setBlockedIn('cn')
                blockedCN.append(bridge.fingerprint)

            if self.coinFlip():
                bridge.setBlockedIn('ir')
                blockedIR.append(bridge.fingerprint)

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
