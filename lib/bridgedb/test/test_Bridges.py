# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: please also see AUTHORS file
# :copyright: (c) 2007-2014, The Tor Project, Inc.
#             (c) 2007-2014, all entities within the AUTHORS file
# :license: 3-Clause BSD, see LICENSE for licensing information

"""Unittests for the :mod:`bridgedb.EmailServer` module."""

import ipaddr
from binascii import a2b_hex

from twisted.trial import unittest

from bridgedb import Bridges
from bridgedb.parse.addr import PortList

import hashlib
try:
    from cStringIO import StringIO
except ImportError:
    from io import StringIO


class BridgeClassTest(unittest.TestCase):
    """Tests for :class:`bridgedb.Bridges.Bridge`."""

    def setUp(self):
        self.nickname = 'unnamed'
        self.ip = ipaddr.IPAddress('127.0.0.1')
        self.orport = '9001'
        self.fingerprint = 'a1cc8dfef1fa11af9c40af1054df9daf45250556'
        self.id_digest = a2b_hex(self.fingerprint)
        self.or_addresses = {ipaddr.IPAddress('6.6.6.6'): PortList(6666),
                             ipaddr.IPAddress('42.1.42.1'): PortList(443)}

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

    def test_getID(self):
        bridge = Bridges.Bridge(self.nickname, self.ip, self.orport,
                                self.fingerprint)
        self.assertEqual(self.id_digest, bridge.getID())

    def test_setDescriptorDigest(self):
        """Test setting the server-descriptor digest value."""
        bridge = Bridges.Bridge(self.nickname, self.ip, self.orport,
                                self.fingerprint)
        testtext = 'thisisatest'
        bridge.setDescriptorDigest(testtext)
        self.assertEqual(bridge.desc_digest, testtext)

    def test_setExtraInfoDigest(self):
        """Test setting the extra-info digest value."""
        bridge = Bridges.Bridge(self.nickname, self.ip, self.orport,
                                self.fingerprint)
        testtext = 'thisisatest'
        bridge.setExtraInfoDigest(testtext)
        self.assertEqual(bridge.ei_digest, testtext)

    def test_setVerified(self):
        """Test setting the `verified` attribute on a Bridge."""
        bridge = Bridges.Bridge(self.nickname, self.ip, self.orport,
                                self.fingerprint)
        bridge.setVerified()
        self.assertTrue(bridge.isVerified())
        self.assertTrue(bridge.verified)
        self.assertEqual(self.id_digest, bridge.getID())

    def test_setRunningStable(self):
        """Test setting the `running` and `stable` attributes on a Bridge."""
        bridge = Bridges.Bridge(self.nickname, self.ip, self.orport,
                                self.fingerprint)
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

    def test_splitterBridgeInsertion(self):
        key = "Testing-Bridges-To-Rings"
        splitter = Bridges.FilteredBridgeSplitter(key)

        bridge1 = Bridges.Bridge('unamed1', '1.2.3.5', 9100,
                            'a1cc8dfef1fa11af9c40af1054df9daf45250550')
        bridge1.setStatus(running = True)
        bridge2 = Bridges.Bridge('unamed2', '1.2.3.4', 8080,
                            'a1cc8dfef1fa11af9c40af1054df9daf45250551')
        bridge2.setStatus(running = True)
        bridge3 = Bridges.Bridge('unamed3', '5.2.3.4', 8080,
                            'b1cc8dfef1fa11af9c40af1054df9daf45250552')
        bridge3.setStatus(running = True)
        bridge4 = Bridges.Bridge('unamed3', '5.2.3.4', 8080,
                            'b1cc8dfef1fa11af9c40af1054df9daf45250552')
        bridge4.setStatus(running = True)

        self.failUnlessEqual(len(splitter), 0)
        splitter.insert(bridge1)
        splitter.insert(bridge2)
        splitter.insert(bridge3)
        # Check that all were inserted
        self.failUnlessEqual(len(splitter), 3)
        splitter.insert(bridge1)
        # Check that the same bridge is not inserted twice
        self.failUnlessEqual(len(splitter), 3)
        splitter.insert(bridge4)
        # Check that identical bridges are not inserted twice
        self.failUnlessEqual(len(splitter), 3)
