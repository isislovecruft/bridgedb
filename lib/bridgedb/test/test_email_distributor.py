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

from twisted.trial import unittest

from bridgedb import Storage
from bridgedb.email import distributor
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
        self.db = bridgedb.Storage.Database(self.fname)
        Storage.setDB(self.db)
        self.cur = self.db._conn.cursor()

        self.bridges = BRIDGES
        self.key = 'aQpeOFIj8q20s98awfoiq23rpOIjFaqpEWFoij1X'
        self.domainmap = {
            'example.com':      'example.com',
            'dkim.example.com': 'dkim.example.com'},
        }
        self.domainrules = {
            'example.com':      ['ignore_dots'],
            'dkim.example.com': ['dkim', 'ignore_dots']}

    def tearDown(self):
        self.db.close()
        os.close(self.fd)
        os.unlink(self.fname)

    def test_EmailDistributor_rate_limit(self):
        """A client's first email should return bridges.  The second should
        return a warning, and the third should receive no response.
        """
        dist = EmailDistributor(self.key, self.domainmap, self.domainrules)
        [dist.hashring.insert(bridge) for bridge in self.bridges]

        # The first request should get a response with bridges
        bridges = d.getBridges('abc@example.com', 1)
        self.assertGreater(len(bridges), 0)
        for b in bridges:
            self.assertIsInstance(b, Bridge)
        self.assertEqual(len(bridges), 3)

        # The second gets a warning, and the third is ignored
        self.assertRaises(TooSoonEmail, d.getBridges, 'abc@example.com', 1)
        self.assertRaises(IgnoreEmail,  d.getBridges, 'abc@example.com', 1)

    def test_EmailDistributor_unsupported_domain(self):
        """An unsupported domain should raise an UnsupportedDomain exception."""
        self.assertRaises(UnsupportedDomain, normalizeEmail,
                          'bad@email.com', self.domainmap, self.domainrules)
