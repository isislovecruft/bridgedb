# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2013-2014, Isis Lovecruft
#             (c) 2007-2014, The Tor Project, Inc.
# :license: 3-Clause BSD, see LICENSE for licensing information

"""Unittests for the :mod:`bridgedb.hashring` module."""

from twisted.trial import unittest

from bridgedb import hashring


class HashringTests(unittest.TestCase):
    """Unittests for :class:`bridgedb.hashring.Hashring`."""

    def test_Hashring_init(self):
        pass

    def test_Hashring_init_name_attribute(self):
        """New ``Hashring``s should have a ``name`` attribute set to 'Ring'."""
        ring = hashring.Hashring('mimsyweretheborogroves')
        self.assertEquals(ring.name, "Ring")

    def test_Hashring_setName(self):
        """Hashring.setName() should set the name attribute."""
        ring = hashring.Hashring('mimsyweretheborogroves')
        ring.setName('borogroves')
        self.assertEquals(ring.name, "borogroves")

    def test_Hashring_setName_two_subrings(self):
        """Hashring.setName() should set the name attribute for subrings."""
        key = 'andmomedidrathsoutgrabe'
        ring = hashring.Hashring(key)
        subring0 = hashring.Hashring(key)
        subring1 = hashring.Hashring(key)
        ring.addSubring(subring0, 'port-443')
        ring.addSubring(subring1, 'flag-Stable')

        ring.setName('raths')
        self.assertEquals(ring.name, 'raths')
        subring0Tuple = ring.subrings[0]
        subring1Tuple = ring.subrings[1]
        firstSubring = subring0Tuple[3]
        secondSubring = subring1Tuple[3]
        self.assertEquals(firstSubring.name, 'raths (port-443 subring)')
        self.assertEquals(secondSubring.name, 'raths (flag-Stable subring)')

    def test_Hashring_clear_subrings(self):
        """Hashring.clear() should also clear subrings."""
        self.skip = True
        raise unittest.SkipTest("This test crashes some systems.")

        # key = 'clearsubringstoo'
        # ring = hashring.Hashring(key)
        # subring0 = hashring.Hashring(key)
        # subring1 = hashring.Hashring(key)
        # ring.addSubring(subring0)
        # self.assertEqual(len(ring.subrings), 1)
        # ring.addSubring(subring1)
        # self.assertEqual(len(ring.subrings), 2)
        # ring.clear()
        # self.assertEqual(len(ring.subrings), 0)
