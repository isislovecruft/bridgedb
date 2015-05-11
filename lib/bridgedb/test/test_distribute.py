# -*- coding: utf-8  -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013-2015, Isis Lovecruft
#             (c) 2007-2015, The Tor Project, Inc.
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""Unittests for :mod:`bridgedb.distribute`."""

from __future__ import print_function

from twisted.trial import unittest

from zope.interface.verify import verifyObject

from bridgedb.distribute import IDistribute
from bridgedb.distribute import Distributor


class DistributorTests(unittest.TestCase):
    """Tests for :class:`bridgedb.distribute.Distributor`."""

    def test_Distributor_implements_IDistribute(self):
        IDistribute.namesAndDescriptions()
        IDistribute.providedBy(Distributor)
        self.assertTrue(verifyObject(IDistribute, Distributor()))

    def test_Distributor_str_no_name(self):
        """str(dist) when the distributor doesn't have a name should return a
        blank string.
        """
        dist = Distributor()
        self.assertEqual(str(dist), "")

    def test_Distributor_str_with_name(self):
        """str(dist) when the distributor has a name should return the name."""
        dist = Distributor()
        dist.name = "foo"
        self.assertEqual(str(dist), "foo")
