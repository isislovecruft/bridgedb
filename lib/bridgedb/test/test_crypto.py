# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013, Isis Lovecruft
#             (c) 2007-2013, The Tor Project, Inc.
#             (c) 2007-2013, all entities within the AUTHORS file
# :license: 3-Clause BSD, see LICENSE for licensing information

"""Unittests for :mod:`bridgedb.crypto`."""

from __future__ import print_function
from __future__ import unicode_literals

import os

from twisted.trial import unittest
from bridgedb import crypto


SEKRIT_KEY  = b'v\x16Xm\xfc\x1b}\x063\x85\xaa\xa5\xf9\xad\x18\xb2P\x93\xc6k\xf9'
SEKRIT_KEY += b'\x8bI\xd9\xb8xw\xf5\xec\x1b\x7f\xa8'


class CryptoTest(unittest.TestCase):

    def test_getKey_nokey(self):
        """Test retrieving the secret_key from an empty file."""
        filename = os.path.join(os.getcwd(), 'sekrit')
        key = crypto.getKey(filename)
        self.failUnlessIsInstance(key, basestring,
                                  "key isn't a string! type=%r" % type(key))

    def test_getKey_tmpfile(self):
        """Test retrieving the secret_key from a new tmpfile."""
        filename = self.mktemp()
        key = crypto.getKey(filename)
        self.failUnlessIsInstance(key, basestring,
                                  "key isn't a string! type=%r" % type(key))

    def test_getKey_keyexists(self):
        """Write the example key to a file and test reading it back."""
        filename = self.mktemp()
        with open(filename, 'wb') as fh:
            fh.write(SEKRIT_KEY)
            fh.flush()

        key = crypto.getKey(filename)
        self.failUnlessIsInstance(key, basestring,
                                  "key isn't a string! type=%r" % type(key))
        self.assertEqual(SEKRIT_KEY, key,
                         """The example key and the one read from file differ!
                         key (in hex): %s
                         SEKRIT_KEY (in hex): %s"""
                         % (key.encode('hex'), SEKRIT_KEY.encode('hex')))
