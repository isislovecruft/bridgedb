# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2013-2015 Isis Lovecruft
#             (c) 2007-2015, The Tor Project, Inc.
# :license: see included LICENSE for information

"""Tests for :mod:`bridgedb.email.distributor`."""

from __future__ import print_function

import logging
import tempfile
import os

from twisted.internet.task import Clock
from twisted.trial import unittest

import bridgedb.Storage

from bridgedb.bridges import Bridge
from bridgedb.email.distributor import EmailDistributor
from bridgedb.email.distributor import IgnoreEmail
from bridgedb.email.distributor import TooSoonEmail
from bridgedb.email.request import EmailBridgeRequest
from bridgedb.parse.addr import BadEmail
from bridgedb.parse.addr import UnsupportedDomain
from bridgedb.parse.addr import normalizeEmail

from .util import generateFakeBridges

logging.disable(50)


BRIDGES = generateFakeBridges()


class EmailDistributorTests(unittest.TestCase):
    """Tests for :class:`bridgedb.email.distributor.EmailDistributor`."""

    # Fail any tests which take longer than 15 seconds.
    timeout = 15

    def setUp(self):
        self.fd, self.fname = tempfile.mkstemp(suffix=".sqlite", dir=os.getcwd())
        bridgedb.Storage.initializeDBLock()
        self.db = bridgedb.Storage.openDatabase(self.fname)
        bridgedb.Storage.setDBFilename(self.fname)

        self.bridges = BRIDGES
        self.key = 'aQpeOFIj8q20s98awfoiq23rpOIjFaqpEWFoij1X'
        self.domainmap = {
            'example.com':      'example.com',
            'dkim.example.com': 'dkim.example.com',
        }
        self.domainrules = {
            'example.com':      ['ignore_dots'],
            'dkim.example.com': ['dkim', 'ignore_dots']
        }

    def tearDown(self):
        self.db.close()
        os.close(self.fd)
        os.unlink(self.fname)

    def makeClientRequest(self, clientEmailAddress):
        bridgeRequest = EmailBridgeRequest()
        bridgeRequest.client = clientEmailAddress
        bridgeRequest.isValid(True)
        bridgeRequest.generateFilters()
        return bridgeRequest

    def test_EmailDistributor_getBridges_default_client(self):
        """If EmailBridgeRequest.client was not set, then getBridges() should
        raise a bridgedb.parse.addr.BadEmail exception.
        """
        dist = EmailDistributor(self.key, self.domainmap, self.domainrules)
        [dist.hashring.insert(bridge) for bridge in self.bridges]

        # The "default" client is literally the string "default", see
        # bridgedb.bridgerequest.BridgeRequestBase.
        bridgeRequest = self.makeClientRequest('default')

        self.assertRaises(BadEmail, dist.getBridges, bridgeRequest, 1)

    def test_EmailDistributor_getBridges_with_whitelist(self):
        """If an email address is in the whitelist, it should get a response
        every time it asks (i.e. no rate-limiting).
        """
        # The whitelist should be in the form {EMAIL: GPG_FINGERPRINT}
        whitelist = {'white@list.ed': '0123456789ABCDEF0123456789ABCDEF01234567'}
        dist = EmailDistributor(self.key, self.domainmap, self.domainrules,
                                whitelist=whitelist)
        [dist.hashring.insert(bridge) for bridge in self.bridges]

        # A request from a whitelisted address should always get a response.
        bridgeRequest = self.makeClientRequest('white@list.ed')
        for i in range(5):
            bridges = dist.getBridges(bridgeRequest, 1)
            self.assertEqual(len(bridges), 3)

    def test_EmailDistributor_getBridges_rate_limit_multiple_clients(self):
        """Each client should be rate-limited separately."""
        dist = EmailDistributor(self.key, self.domainmap, self.domainrules)
        [dist.hashring.insert(bridge) for bridge in self.bridges]

        bridgeRequest1 = self.makeClientRequest('abc@example.com')
        bridgeRequest2 = self.makeClientRequest('def@example.com')
        bridgeRequest3 = self.makeClientRequest('ghi@example.com')

        # The first request from 'abc' should get a response with bridges.
        self.assertEqual(len(dist.getBridges(bridgeRequest1, 1)), 3)
        # The second from 'abc' gets a warning.
        self.assertRaises(TooSoonEmail, dist.getBridges, bridgeRequest1, 1)
        # The first request from 'def' should get a response with bridges.
        self.assertEqual(len(dist.getBridges(bridgeRequest2, 1)), 3)
        # The third from 'abc' is ignored.
        self.assertRaises(IgnoreEmail,  dist.getBridges, bridgeRequest1, 1)
        # The second from 'def' gets a warning.
        self.assertRaises(TooSoonEmail, dist.getBridges, bridgeRequest2, 1)
        # The third from 'def' is ignored.
        self.assertRaises(IgnoreEmail,  dist.getBridges, bridgeRequest2, 1)
        # The fourth from 'abc' is ignored.
        self.assertRaises(IgnoreEmail,  dist.getBridges, bridgeRequest1, 1)
        # The first request from 'ghi' should get a response with bridges.
        self.assertEqual(len(dist.getBridges(bridgeRequest3, 1)), 3)
        # The second from 'ghi' gets a warning.
        self.assertRaises(TooSoonEmail, dist.getBridges, bridgeRequest3, 1)
        # The third from 'ghi' is ignored.
        self.assertRaises(IgnoreEmail,  dist.getBridges, bridgeRequest3, 1)
        # The fourth from 'ghi' is ignored.
        self.assertRaises(IgnoreEmail,  dist.getBridges, bridgeRequest3, 1)

    def test_EmailDistributor_getBridges_rate_limit(self):
        """A client's first email should return bridges.  The second should
        return a warning, and the third should receive no response.
        """
        dist = EmailDistributor(self.key, self.domainmap, self.domainrules)
        [dist.hashring.insert(bridge) for bridge in self.bridges]

        bridgeRequest = self.makeClientRequest('abc@example.com')

        # The first request should get a response with bridges.
        bridges = dist.getBridges(bridgeRequest, 1)
        self.assertGreater(len(bridges), 0)
        [self.assertIsInstance(b, Bridge) for b in bridges]
        self.assertEqual(len(bridges), 3)

        # The second gets a warning, and the third is ignored.
        self.assertRaises(TooSoonEmail, dist.getBridges, bridgeRequest, 1)
        self.assertRaises(IgnoreEmail,  dist.getBridges, bridgeRequest, 1)

    def test_EmailDistributor_getBridges_rate_limit_expiry(self):
        """A client's first email should return bridges.  The second should
        return a warning, and the third should receive no response.  After the
        EmailDistributor.emailRateMax is up, the client should be able to
        receive a response again.
        """
        clock = Clock()
        dist = EmailDistributor(self.key, self.domainmap, self.domainrules)
        [dist.hashring.insert(bridge) for bridge in self.bridges]

        bridgeRequest = self.makeClientRequest('abc@example.com')

        # The first request should get a response with bridges.
        self.assertEqual(len(dist.getBridges(bridgeRequest, 1, clock)), 3)
        # The second gets a warning, and the rest are ignored.
        self.assertRaises(TooSoonEmail, dist.getBridges, bridgeRequest, 1, clock)
        self.assertRaises(IgnoreEmail,  dist.getBridges, bridgeRequest, 1, clock)
        self.assertRaises(IgnoreEmail,  dist.getBridges, bridgeRequest, 1, clock)
        self.assertRaises(IgnoreEmail,  dist.getBridges, bridgeRequest, 1, clock)

        clock.advance(2 * dist.emailRateMax)

        # The client should again a response with bridges.
        self.assertEqual(len(dist.getBridges(bridgeRequest, 1)), 3, clock)

    def test_EmailDistributor_cleanDatabase(self):
        """Calling cleanDatabase() should cleanup email times in database, but
        not allow clients who have been recently warned and/or ignored to
        receive a response again until the remainder of their MAX_EMAIL_RATE
        time is up.
        """
        dist = EmailDistributor(self.key, self.domainmap, self.domainrules)
        [dist.hashring.insert(bridge) for bridge in self.bridges]

        bridgeRequest = self.makeClientRequest('abc@example.com')

        # The first request should get a response with bridges.
        self.assertEqual(len(dist.getBridges(bridgeRequest, 1)), 3)
        # The second gets a warning, and the third is ignored.
        self.assertRaises(TooSoonEmail, dist.getBridges, bridgeRequest, 1)
        self.assertRaises(IgnoreEmail,  dist.getBridges, bridgeRequest, 1)

        dist.cleanDatabase()

        # Cleaning the warning email times in the database shouldn't cause
        # 'abc@example.com' to be able to email again, because only the times
        # which aren't older than EMAIL_MAX_RATE should be cleared.
        self.assertRaises(IgnoreEmail,  dist.getBridges, bridgeRequest, 1)

    def test_EmailDistributor_prepopulateRings(self):
        """Calling prepopulateRings() should add two rings to the
        EmailDistributor.hashring.
        """
        dist = EmailDistributor(self.key, self.domainmap, self.domainrules)

        # There shouldn't be any subrings yet.
        self.assertEqual(len(dist.hashring.filterRings), 0)

        dist.prepopulateRings()

        # There should now be two subrings, but the subrings should be empty.
        self.assertEqual(len(dist.hashring.filterRings), 2)
        for (filtre, subring) in dist.hashring.filterRings.values():
            self.assertEqual(len(subring), 0)

        # The subrings in this Distributor have gross names, because the
        # filter functions (including their addresses in memory!) are used as
        # the subring names.  In this case, we should have something like:
        #
        #     frozenset([<function byIPv6 at 0x7eff7ad7fc80>])
        #
        # and
        #
        #     frozenset([<function byIPv4 at 0x7eff7ad7fc08>])
        #
        # So we have to join the strings together and check the whole thing,
        # since we have no other way to use these stupid subring names to
        # index into the dictionary they are stored in, because the memory
        # addresses are unknowable until runtime.

        # There should be an IPv4 subring and an IPv6 ring:
        ringnames = dist.hashring.filterRings.keys()
        self.failUnlessIn("IPv4", "".join([str(ringname) for ringname in ringnames]))
        self.failUnlessIn("IPv6", "".join([str(ringname) for ringname in ringnames]))

        [dist.hashring.insert(bridge) for bridge in self.bridges]

        # There should still be two subrings.
        self.assertEqual(len(dist.hashring.filterRings), 2)
        for (filtre, subring) in dist.hashring.filterRings.values():
            self.assertGreater(len(subring), 0)

        # Ugh, the hashring code is so gross looking.
        subrings = dist.hashring.filterRings
        subring1 = subrings.values()[0][1]
        subring2 = subrings.values()[1][1]
        # Each subring should have roughly the same number of bridges.
        # (Having ±10 bridges in either ring, out of 500 bridges total, should
        # be so bad.)
        self.assertApproximates(len(subring1), len(subring2), 10)

    def test_EmailDistributor_unsupported_domain(self):
        """An unsupported domain should raise an UnsupportedDomain exception."""
        self.assertRaises(UnsupportedDomain, normalizeEmail,
                          'bad@email.com', self.domainmap, self.domainrules)
