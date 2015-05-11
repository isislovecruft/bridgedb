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
from bridgedb.test.util import generateFakeBridges

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
        self.assertEqual(len(dist.getBridges(bridgeRequest, 1)), 3)

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

    def test_EmailDistributor_regenerateCaches(self):
        """Calling regenerateCaches() should add two rings to the
        EmailDistributor.hashring.
        """
        dist = EmailDistributor(self.key, self.domainmap, self.domainrules)
        # There should be subrings equal to the number of supported domains.
        self.assertEqual(len(dist.hashring.subrings), len(dist.supportedDomains))

        dist.regenerateCaches()

        # There should still be subrings equal to the number of supported
        # domains, and the subrings should be empty.
        self.assertEqual(len(dist.hashring.subrings), len(dist.supportedDomains))
        for subring in dist.hashring.subrings:
            self.assertEqual(len(subring), 0)

        # There should be an IPv4 subring and an IPv6 ring in the cache:
        cachenames = [k for sub in dist.hashring.subrings for k in sub.cache.keys()]
        self.failUnlessIn("ipv6", " ".join(cachenames))
        self.failUnlessIn("ipv4", " ".join(cachenames))

        [dist.hashring.insert(bridge) for bridge in self.bridges]

        # There should still be subrings equal to the number of supported
        # domains.  However, the subrings should not be empty.
        self.assertEqual(len(dist.hashring.subrings), len(dist.supportedDomains))
        for subring in dist.hashring.subrings:
            self.assertGreater(len(subring), 0)

        # Specifically, it should have length two, for our test cases:
        self.assertEqual(len(dist.hashring.subrings), 2)
        subring0 = dist.hashring.subrings[0]
        subring1 = dist.hashring.subrings[1]
        # Each subring should have roughly the same number of bridges.
        # (Having ±50 bridges in either ring, out of 500 bridges total, should
        # be so bad.)
        self.assertApproximates(len(subring0), len(subring1), 50)

    def test_EmailDistributor_unsupported_domain(self):
        """An unsupported domain should raise an UnsupportedDomain exception."""
        self.assertRaises(UnsupportedDomain, normalizeEmail,
                          'bad@email.com', self.domainmap, self.domainrules)
