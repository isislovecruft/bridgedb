# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2017, Isis Lovecruft
#             (c) 2017, The Tor Project, Inc.
# :license: 3-Clause BSD, see LICENSE for licensing information

"""Unittests for :class:`bridgedb.parse.blacklist` module."""

from __future__ import print_function

import logging
import os

from bridgedb.parse import blacklist

BLACKLIST_ENTRIES = """\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA doing bad stuff
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB b-b-b-b-bad to the bone
CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC invalid fingerprint
DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
"""

from twisted.trial import unittest
from twisted.trial.unittest import SkipTest

logging.disable(50)


class ParseBridgeBlacklistFileTests(unittest.TestCase):
    """Unittests for :func:`bridgedb.parse.blacklist.parseBridgeBlacklistFile`."""

    def setUp(self):
        self.fh = "TEST-blacklisted-bridges"

        with open(self.fh, 'w') as fh:
            fh.write(BLACKLIST_ENTRIES)
            fh.flush()

    def test_parseBridgeBlacklistFile(self):
        blacklisted = blacklist.parseBridgeBlacklistFile(self.fh)

        self.assertIn("A"*40, blacklisted.keys())
        self.assertIn("B"*40, blacklisted.keys())
        self.assertNotIn("C"*40, blacklisted.keys())
        self.assertIn("D"*40, blacklisted.keys())

        self.assertEqual(blacklisted.get("A"*40), "doing bad stuff")
        self.assertEqual(blacklisted.get("B"*40), "b-b-b-b-bad to the bone")
        self.assertEqual(blacklisted.get("D"*40), "")

    def tearDown(self):
        if os.path.isfile(self.fh):
            os.unlink(self.fh)
