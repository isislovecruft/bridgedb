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

from bridgedb.bridgerequest import IRequestBridges
from bridgedb.https import request 


class MockRequest(object):
    def __init__(self, args):
        self.args = args


class HTTPSBridgeRequestTests(unittest.TestCase):
    """Unittests for :class:`bridgedb.https.request.HTTPSBridgeRequest`."""

    def setUp(self):
        """Setup test run."""
        self.request = request.HTTPSBridgeRequest()

    def test_HTTPSBridgeRequest_implements_IRequestBridges(self):
        """HTTPSBridgeRequest should implement IRequestBridges interface."""
        self.assertTrue(IRequestBridges.implementedBy(request.HTTPSBridgeRequest))

    def test_HTTPSBridgeRequest_withIPversion(self):
        """HTTPSBridgeRequest.withIPversion({ipv6=[…]}) should store that the
        client wanted IPv6 bridges."""
        parameters = {'ipv6': 'wooooooooo'}
        self.request.withIPversion(parameters)

    def test_HTTPSBridgeRequest_withoutBlockInCountry_IR(self):
        """HTTPSBridgeRequest.withoutBlockInCountry() should add the country CC
        to the ``notBlockedIn`` attribute.
        """
        httprequest = MockRequest({'unblocked': ['ir']})
        self.request.withoutBlockInCountry(httprequest)
        self.assertIn('ir', self.request.notBlockedIn)

    def test_HTTPSBridgeRequest_withoutBlockInCountry_US(self):
        """HTTPSBridgeRequest.withoutBlockInCountry() should add the country CC
        to the ``notBlockedIn`` attribute (and not any other countries).
        """
        httprequest = MockRequest({'unblocked': ['us']})
        self.request.withoutBlockInCountry(httprequest)
        self.assertNotIn('ir', self.request.notBlockedIn)

    def test_HTTPSBridgeRequest_withoutBlockInCountry_no_addClientCountryCode(self):
        """HTTPSBridgeRequest.withoutBlockInCountry(), when
        addClientCountryCode=False, shouldn't add the client's country code to the
        ``notBlockedIn`` attribute.
        """
        httprequest = MockRequest({'unblocked': ['nl']})
        self.request = request.HTTPSBridgeRequest(addClientCountryCode=False)
        self.request.client = '5.5.5.5'
        self.request.withoutBlockInCountry(httprequest)
        self.assertItemsEqual(['nl'], self.request.notBlockedIn)

    def test_HTTPSBridgeRequest_withoutBlockInCountry_bad_params(self):
        """HTTPSBridgeRequest.withoutBlockInCountry() should stop processing if
        the request had a bad "unblocked" parameter.
        """
        httprequest = MockRequest({'unblocked': [3,]})
        self.request.withoutBlockInCountry(httprequest)
        self.assertNotIn('IR', self.request.notBlockedIn)

    def test_HTTPSBridgeRequest_withPluggableTransportType(self):
        """HTTPSBridgeRequest.withPluggableTransportType() should add the
        pluggable transport type to the ``transport`` attribute.
        """
        httprequest = MockRequest({'transport': ['huggable_transport']})
        self.request.withPluggableTransportType(httprequest.args)
        self.assertIn('huggable_transport', self.request.transports)

    def test_HTTPSBridgeRequest_withPluggableTransportType_bad_param(self):
        """HTTPSBridgeRequest.withPluggableTransportType() should stop
        processing if the request had a bad "unblocked" parameter.
        """
        httprequest = MockRequest({'transport': [3,]})
        self.request.withPluggableTransportType(httprequest.args)
        self.assertNotIn('huggable_transport', self.request.transports)
