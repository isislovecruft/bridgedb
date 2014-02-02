# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: please also see AUTHORS file
# :copyright: (c) 2007-2013, The Tor Project, Inc.
#             (c) 2007-2013, all entities within the AUTHORS file
# :license: 3-Clause BSD, see LICENSE for licensing information

"""Unittests for the :mod:`bridgedb.EmailServer` module."""

from twisted.trial import unittest
from binascii import a2b_hex
from bridgedb import Bridges
import hashlib
try:
    from cStringIO import StringIO
except ImportError:
    from io import StringIO

class BridgeClassTest(unittest.TestCase):
    """Tests for :class:`bridgedb.Bridges.Bridge`."""

    def setUp(self):
        self.nickname = 'unnamed'
        self.ip = '127.0.0.1'
        self.orport = '9001'
        self.fingerprint = 'a1cc8dfef1fa11af9c40af1054df9daf45250556'
        self.id_digest = a2b_hex(self.fingerprint)
        self.or_addresses = {}

    def test_init(self):
        try:
            Bridges.Bridge(self.nickname, self.ip, self.orport,
                           fingerprint=self.fingerprint)
            Bridges.Bridge(self.nickname, self.ip, self.orport,
                           id_digest=self.id_digest)
        except Exception as e:
            self.fail("Unexpected %s exception." % type(e))

        self.failUnlessRaises(TypeError, Bridges.Bridge,
                              self.nickname, self.ip, self.orport,
                              id_digest=self.id_digest[:-1])

        self.failUnlessRaises(TypeError, Bridges.Bridge,
                              self.nickname, self.ip, self.orport,
                              fingerprint=self.fingerprint[:-1])

        self.failUnlessRaises(TypeError, Bridges.Bridge,
                              self.nickname, self.ip, self.orport)

        invalid_fingerprint = self.fingerprint[:-1] + 'q'
        self.failUnlessRaises(TypeError, Bridges.Bridge, self.nickname,
                              self.ip, self.orport,
                              fingerprint=invalid_fingerprint)

    def test_Bridgehelperfunctions(self):
        bridge = Bridges.Bridge(self.nickname, self.ip, self.orport,
                                self.fingerprint)
        self.assertEqual(self.id_digest, bridge.getID())

        testtext = 'thisisatest'
        bridge.setDescriptorDigest(testtext)
        self.assertEqual(bridge.desc_digest, testtext)
        bridge.setExtraInfoDigest(testtext)
        self.assertEqual(bridge.ei_digest, testtext)
        bridge.setVerified()
        self.assertTrue(bridge.isVerified())
        self.assertTrue(bridge.verified)
        self.assertEqual(self.id_digest, bridge.getID())

        self.assertFalse(bridge.running)
        self.assertFalse(bridge.stable)
        bridge.setStatus(True, True)
        self.assertTrue(bridge.running)
        self.assertTrue(bridge.stable)

#    def test_isBlocked(self):
        

    def test_getDescriptorDigests(self):
        sha1hash = hashlib.sha1()
        ei_digest = 'abcdefghijklmno'

        test = "this is a test line\nFollowed by another\n"
        test += "extra-info-digest %s\n" % ei_digest
        sha1hash.update(test)
        digest = sha1hash.hexdigest()
        test += "-----BEGIN SIGNATURE-----\n"
        test += "This is a test line that should be skipped\n"
        test += "-----END SIGNATURE-----\n"
        digests = Bridges.getDescriptorDigests(StringIO(test))
        self.failUnlessIn(digest, digests)
        self.failUnlessEqual(ei_digest, digests[digest])

    def test_getExtraInfoDigests(self):
        sha1hash = hashlib.sha1()

        test = "Many words and line all together\n"
        test += "extra info is nothing like weather\n"
        test += "it's certain to come, like the key in a hum\n"
        test += "but sometimes without a transport and rum\n"
        content = test
        sha1hash.update(test)
        digest = sha1hash.hexdigest()
        test += "-----BEGIN SIGNATURE-----\n"
        test += "But the rum can't save the world like you\n"
        test += "-----END SIGNATURE-----\n"
        digests = Bridges.getExtraInfoDigests(StringIO(test))
        self.failUnlessIn(digest, digests)
        self.failUnlessEqual(content, digests[digest].read())
