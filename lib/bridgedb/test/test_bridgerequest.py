# -*- coding: utf-8 -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2015, The Tor Project, Inc.
#             (c) 2014-2015, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________


from twisted.trial import unittest

from bridgedb import bridgerequest
from bridgedb.bridgerequest import IRequestBridges
from bridgedb.bridgerequest import BridgeRequestBase


class BridgeRequestBaseTests(unittest.TestCase):
    """Unittests for :class:`bridgedb.bridgerequest.BridgeRequestBase`."""

    def setUp(self):
        """Setup test run."""
        self.request = BridgeRequestBase()

    def test_BridgeRequestBase_implements_IRequestBridges(self):
        """BridgeRequestBase should implement IRequestBridges interface."""
        self.assertTrue(IRequestBridges.implementedBy(BridgeRequestBase))

    def test_BridgeRequestBase_withoutBlockInCountry(self):
        """BridgeRequestBase.withoutBlockInCountry() should add the country CC
        to the ``notBlockedIn`` attribute.
        """
        self.request.withoutBlockInCountry('US')
        self.assertIn('US', self.request.notBlockedIn)

    def test_BridgeRequestBase_withPluggableTransportType(self):
        """BridgeRequestBase.withPluggableTransportType() should add the
        pluggable transport type to the ``transport`` attribute.
        """
        self.request.withPluggableTransportType('huggable-transport')
        self.assertIn('huggable-transport', self.request.transports)
