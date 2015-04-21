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

from twisted.trial import unittest

import bridgedb.Storage

from bridgedb.bridges import Bridge
from bridgedb.email.distributor import EmailDistributor
from bridgedb.email.distributor import IgnoreEmail
from bridgedb.email.distributor import TooSoonEmail
from bridgedb.email.request import EmailBridgeRequest
from bridgedb.parse.addr import UnsupportedDomain
from bridgedb.parse.addr import normalizeEmail
from bridgedb.test.util import generateFakeBridges

logging.disable(50)


BRIDGES = generateFakeBridges()


class EmailDistributorTests(unittest.TestCase):
    """Tests for :class:`bridgedb.email.distributor.EmailDistributor`."""

    def setUp(self):
        self.fd, self.fname = tempfile.mkstemp()
        bridgedb.Storage.initializeDBLock()
        self.db = bridgedb.Storage.openDatabase(self.fname)
        bridgedb.Storage.setDBFilename(self.fname)
        self.cur = self.db.cursor()
        self.db.close()

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

    def test_EmailDistributor_rate_limit(self):
        """A client's first email should return bridges.  The second should
        return a warning, and the third should receive no response.
        """
        dist = EmailDistributor(self.key, self.domainmap, self.domainrules)
        [dist.hashring.insert(bridge) for bridge in self.bridges]

        bridgeRequest = self.makeClientRequest('abc@example.com')

        # The first request should get a response with bridges
        bridges = dist.getBridges(bridgeRequest, 1)
        self.assertGreater(len(bridges), 0)
        [self.assertIsInstance(b, Bridge) for b in bridges]
        self.assertEqual(len(bridges), 3)

        # The second gets a warning, and the third is ignored
        self.assertRaises(TooSoonEmail, dist.getBridges, bridgeRequest, 1)
        self.assertRaises(IgnoreEmail,  dist.getBridges, bridgeRequest, 1)

    def test_EmailDistributor_unsupported_domain(self):
        """An unsupported domain should raise an UnsupportedDomain exception."""
        self.assertRaises(UnsupportedDomain, normalizeEmail,
                          'bad@email.com', self.domainmap, self.domainrules)
