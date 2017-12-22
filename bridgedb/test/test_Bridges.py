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
import ipaddr
import logging

from twisted.trial import unittest

from bridgedb import Bridges
from bridgedb.test import util

# For additional logger output for debugging, comment out the following:
#logging.disable(50)
# and then uncomment the following line:
Bridges.logging.getLogger().setLevel(10)


class BridgeRingTests(unittest.TestCase):
    """Unittests for :class:`bridgedb.Bridges.BridgeRing`."""

    def setUp(self):
        self.ring = Bridges.BridgeRing('fake-hmac-key')

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
