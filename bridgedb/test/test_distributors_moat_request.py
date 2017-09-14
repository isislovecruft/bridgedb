# -*- coding: utf-8 -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2014-2017, Isis Lovecruft
#             (c) 2014-2017, The Tor Project, Inc.
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""Unittests for :mod:`bridgedb.distributors.moat.request`."""

from __future__ import print_function

from twisted.trial import unittest

from bridgedb.distributors.moat import request


class MoatBridgeRequest(unittest.TestCase):
    """Unittests for :class:`bridgedb.distributors.moat.request.MoatBridgeRequest`."""

    def setUp(self):
        self.bridgeRequest = request.MoatBridgeRequest()

    def test_withoutBlockInCountry(self):
        data = {'unblocked': ['us', 'ir', 'sy']}

        self.bridgeRequest.withoutBlockInCountry(data)
        self.bridgeRequest.generateFilters()

        self.assertItemsEqual(['byTransportNotBlockedIn(None,us,4)',
                               'byTransportNotBlockedIn(None,ir,4)',
                               'byTransportNotBlockedIn(None,sy,4)'],
                              [x.__name__ for x in self.bridgeRequest.filters])

    def test_withoutBlockInCountry_not_a_valid_country_code(self):
        data = {'unblocked': ['3']}
        self.bridgeRequest.withoutBlockInCountry(data)

    def test_withoutBlockInCountry_unicode(self):
        data = {'unblocked': ['föö']}
        self.bridgeRequest.withoutBlockInCountry(data)

    def test_withoutBlockInCountry_not_a_valid_transport(self):
        data = {'unblocked': ['3']}
        self.bridgeRequest.withPluggableTransportType(data)

    def test_withPluggableTransportType_unicode(self):
        data = {'transport': 'bifröst'}
        self.bridgeRequest.withPluggableTransportType(data)
