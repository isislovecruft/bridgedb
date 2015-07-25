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
        self.assertIn('us', self.request.notBlockedIn)

    def test_BridgeRequestBase_withPluggableTransportType(self):
        """BridgeRequestBase.withPluggableTransportType() should add the
        pluggable transport type to the ``transport`` attribute.
        """
        self.request.withPluggableTransportType('huggable_transport')
        self.assertIn('huggable_transport', self.request.transports)

    def test_BridgeRequestBase_getHashringPlacement_without_client(self):
        """BridgeRequestBase.getHashringPlacement() without a client parameter
        should use the default client identifier string.
        """
        self.assertEqual(self.request.getHashringPlacement('AAAA'),
                         3486762050L)

    def test_BridgeRequestBase_getHashringPlacement_with_client(self):
        """BridgeRequestBase.getHashringPlacement() with a client parameter
        should use the client identifier string.
        """
        self.assertEqual(self.request.getHashringPlacement('AAAA', client='you'),
                         2870307088L)
