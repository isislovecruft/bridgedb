# -*- coding: utf-8 -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2017, Isis Lovecruft
#             (c) 2017, The Tor Project, Inc.
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""Unittests for :mod:`bridgedb.Bridges`."""

from __future__ import print_function

import copy
import io
import ipaddr
import logging

from twisted.trial import unittest

from bridgedb import Bridges
from bridgedb.test import util

# For additional logger output for debugging, comment out the following:
logging.disable(50)
# and then uncomment the following line:
#Bridges.logging.getLogger().setLevel(10)


class BridgeRingTests(unittest.TestCase):
    """Unittests for :class:`bridgedb.Bridges.BridgeRing`."""

    def setUp(self):
        self.ring = Bridges.BridgeRing('fake-hmac-key')

    def addRandomBridges(self):
        bridges = copy.deepcopy(util.generateFakeBridges())

        [self.ring.insert(bridge) for bridge in bridges]

    def addBridgesFromSameSubnet(self):
        bridges = copy.deepcopy(util.generateFakeBridges())
        subnet = "5.5.%d.%d"
        i = 1
        j = 1

        for bridge in bridges:
            bridge.address = ipaddr.IPAddress(subnet % (i, j))
            self.ring.insert(bridge)

            if j == 255:
                j  = 1
                i += 1
            else:
                j += 1

    def test_filterDistinctSubnets(self):
        """If there are bridges in the same subnet then they should be
        filtered out of the results.
        """
        self.addBridgesFromSameSubnet()

        chosen = self.ring.bridges.keys()[:10]
        bridges = self.ring.filterDistinctSubnets(chosen)

        # Since they're all in the same /16, we should only get one
        # bridge back:
        self.assertEqual(len(bridges), 1)

    def test_filterDistinctSubnets_random_bridges(self):
        """Even after filtering, in a normal case we should get the amount of
        bridges we asked for.  However, we should always get at least one.
        """
        self.addRandomBridges()

        chosen = self.ring.bridges.keys()[:3]
        bridges = self.ring.filterDistinctSubnets(chosen)

        self.assertGreaterEqual(len(bridges), 1)

    def test_clear(self):
        """Clear should get rid of all the inserted bridges."""
        self.addRandomBridges()
        self.assertGreater(len(self.ring), 0)
        self.ring.clear()
        self.assertEqual(len(self.ring), 0)

    def test_getBridges_filterBySubnet(self):
        """We should still get the number of bridges we asked for, even when
        filtering by distinct subnets.
        """
        self.addRandomBridges()
        bridges = self.ring.getBridges('a' * Bridges.DIGEST_LEN, N=3, filterBySubnet=True)
        self.assertEqual(len(bridges), 3)

    def test_dumpAssignments(self):
        """This should dump the bridges to the file."""
        self.addRandomBridges()

        f = io.StringIO()

        self.ring.dumpAssignments(f)

        f.flush()
        f.seek(0)

        data = f.read()
        first = self.ring.bridges.values()[0].fingerprint

        # The first bridge's fingerprint should be within the data somewhere
        self.assertIn(first, data)


class FixedBridgeSplitterTests(unittest.TestCase):
    """Unittests for :class:`bridgedb.Bridges.FixedBridgeSplitter`."""

    def setUp(self):
        self.rings = [Bridges.BridgeRing('fake-hmac-key-1'),
                      Bridges.BridgeRing('fake-hmac-key-2')]
        self.splitter = Bridges.FixedBridgeSplitter('fake-hmac-key', self.rings)

    def addRandomBridges(self):
        bridges = copy.deepcopy(util.generateFakeBridges())

        [self.splitter.insert(bridge) for bridge in bridges]

    def test_insert(self):
        self.addRandomBridges()
        self.assertGreater(len(self.splitter), 0)

    def test_clear(self):
        """Clear should get rid of all the inserted bridges."""
        self.addRandomBridges()
        self.assertGreater(len(self.splitter), 0)
        self.splitter.clear()
        self.assertEqual(len(self.splitter), 0)

    def test_dumpAssignments(self):
        """This should dump the bridges to the file."""
        self.addRandomBridges()

        f = io.StringIO()

        self.splitter.dumpAssignments(f)

        f.flush()
        f.seek(0)

        data = f.read()
        first = self.splitter.rings[0].bridges.values()[0].fingerprint

        # The first bridge's fingerprint should be within the data somewhere
        self.assertIn(first, data)
