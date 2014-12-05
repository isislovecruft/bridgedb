# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2014, The Tor Project, Inc.
#             (c) 2007-2014, all entities within the AUTHORS file
# :license: 3-Clause BSD, see LICENSE for licensing information

"""Unittests for the :mod:`bridgedb.bridges` module."""

from binascii import a2b_hex

import ipaddr
import io
import hashlib
import warnings

from twisted.trial import unittest

from bridgedb import bridges
from bridgedb.Bridges import FilteredBridgeSplitter
from bridgedb.bridgerequest import BridgeRequestBase
from bridgedb.parse.addr import PortList

# Don't print "WARNING:root: Couldn't parse K=V from PT arg: ''" a bunch of
# times while running the tests.
warnings.filterwarnings("ignore", ".*Couldn't parse K=V from PT arg.*", Warning)


class BridgeIntegrationTests(unittest.TestCase):
    """Integration tests to ensure that the new :class:`bridgedb.bridges.Bridge`
    class has compatible behaviour with the expected behaviour of the old
    :class:`bridgedb.Bridges.Bridge` class.

    .. data: OldTest (enum)

    These tests were refactored from the old tests for
    :class:`~bridgedb.test.deprecated.Bridge`, which lived in
    ``lib/bridgedb/test/test_Bridges.py``. For the translations from the old
    tests in ``bridgedb.test.test_Bridges.BridgeClassTest`` to their new
    equivalents here in ``bridgedb.test.test_bridges.BridgeIntegrationTests``,
    which should test for the same things as their old equivalents, see the
    following table:

    ==============================================  ========================
    OldTest                                         Equivalent Test(s) Here
    ==============================================  ========================
    test_init                                       test_integration_init_[0-5]
    test_getID                                      test_integration_getID
    test_setDescriptorDigest                        test_integration_setDescriptorDigest
    test_setExtraInfoDigest                         test_integration_setExtraInfoDigest
    test_setVerified                                test_integration_setVerified
    test_setRunningStable                           test_integration_setRunningStable
    test_getConfigLine_vanilla_withoutFingerprint   test_integration_getConfigLine_vanilla_withoutFingerprint
    test_getConfigLine_vanilla_withFingerprint      test_integration_getConfigLine_vanilla_withFingerprint
    test_getConfigLine_scramblesuit_withFingeprint  test_integration_getConfigLine_scramblesuit_withFingerprint
    test_getDescriptorDigests                       test_integration_getDescriptorDigests
    test_getExtraInfoDigests                        test_integration_getExtraInfoDigests
    test_splitterBridgeInsertion                    test_integration_splitterBridgeInsertion
    ==============================================  ========================
    ..
    """

    def setUp(self):
        self.nickname = 'unnamed'
        self.ip = ipaddr.IPAddress('127.0.0.1')
        self.orport = '9001'
        self.fingerprint = 'a1cc8dfef1fa11af9c40af1054df9daf45250556'
        self.id_digest = a2b_hex(self.fingerprint)
        self.or_addresses = {ipaddr.IPAddress('6.6.6.6'): PortList(6666),
                             ipaddr.IPAddress('42.1.42.1'): PortList(443)}

    def test_integration_init_0(self):
        """Ensure that we can initialise the new :class:`bridgedb.bridges.Bridge`
        class in the same manner as the old :class:`bridgedb.Bridges.Bridge`
        class. This test ensures that initialisation with a fingerprint is
        successful.
        """
        b = bridges.Bridge(self.nickname, self.ip, self.orport,
                           fingerprint=self.fingerprint)
        self.assertIsInstance(b, bridges.Bridge)

    def test_integration_init_1(self):
        """Ensure that we can initialise the new :class:`bridgedb.bridges.Bridge`
        class in the same manner as the old :class:`bridgedb.Bridges.Bridge`
        class. This test ensures that initialisation with a digest of a
        bridge's ID key is successful.
        """
        b = bridges.Bridge(self.nickname, self.ip, self.orport,
                           id_digest=self.id_digest)
        self.assertIsInstance(b, bridges.Bridge)

    def test_integration_init_2(self):
        """Initialisation of a :class:`bridgedb.bridges.Bridge` with a bad
        ``id_digest`` should raise a TypeError.
        """
        self.failUnlessRaises(TypeError, bridges.Bridge,
                              self.nickname, self.ip, self.orport,
                              id_digest=self.id_digest[:-1])

    def test_integration_init_3(self):
        """Initialisation of a :class:`bridgedb.bridges.Bridge` with a bad
        ``fingerprint`` should raise a TypeError.
        """
        self.failUnlessRaises(TypeError, bridges.Bridge,
                              self.nickname, self.ip, self.orport,
                              fingerprint=self.fingerprint[:-1])

    def test_integration_init_4(self):
        """Initialisation of a :class:`bridgedb.bridges.Bridge` with a bad
        ``fingerprint`` should raise a TypeError.
        """
        invalid_fingerprint = self.fingerprint[:-1] + 'q'
        self.failUnlessRaises(TypeError, bridges.Bridge, self.nickname,
                              self.ip, self.orport,
                              fingerprint=invalid_fingerprint)

    def test_integration_init_5(self):
        """Initialisation of a :class:`bridgedb.bridges.Bridge` without either
        a ``fingerprint`` or an ``id_digest`` should raise a TypeError.
        """
        self.failUnlessRaises(TypeError, bridges.Bridge,
                              self.nickname, self.ip, self.orport)

    def test_integration_getID(self):
        """Calling ``bridges.Bridge.getID()`` should return the binary encoded
        ``fingerprint``.
        """
        bridge = bridges.Bridge(self.nickname, self.ip, self.orport,
                                self.fingerprint)
        self.assertEqual(self.id_digest, bridge.getID())

    def test_integration_setDescriptorDigest(self):
        """Test setting the server-descriptor digest value."""
        bridge = bridges.Bridge(self.nickname, self.ip, self.orport,
                                self.fingerprint)
        testtext = 'thisisatest'
        bridge.setDescriptorDigest(testtext)
        self.assertEqual(bridge.desc_digest, testtext)

    def test_integration_setExtraInfoDigest(self):
        """Test setting the extra-info digest value."""
        bridge = bridges.Bridge(self.nickname, self.ip, self.orport,
                                self.fingerprint)
        testtext = 'thisisatest'
        bridge.setExtraInfoDigest(testtext)
        self.assertEqual(bridge.ei_digest, testtext)

    def test_integration_setVerified(self):
        """Test setting the `verified` attribute on a Bridge."""
        raise unittest.SkipTest(
            ("The setVerified() and isVerified() methods were not refactored "
             "into the new bridgedb.bridges.Bridge class, as it's not clear "
             "yet if they are necessary. Skip these tests for now."))

        bridge = bridges.Bridge(self.nickname, self.ip, self.orport,
                                self.fingerprint)
        bridge.setVerified()
        self.assertTrue(bridge.isVerified())
        self.assertTrue(bridge.verified)
        self.assertEqual(self.id_digest, bridge.getID())

    def test_integration_setRunningStable(self):
        """Test setting the `running` and `stable` attributes on a Bridge."""
        bridge = bridges.Bridge(self.nickname, self.ip, self.orport,
                                self.fingerprint)
        self.assertFalse(bridge.running)
        self.assertFalse(bridge.stable)
        bridge.setStatus(True, True)
        self.assertTrue(bridge.running)
        self.assertTrue(bridge.stable)

    def test_integration_getConfigLine_vanilla_withoutFingerprint(self):
        """Should return a config line without a fingerprint."""
        #self.skip = True
        bridge = bridges.Bridge('nofpr', '23.23.23.23', 2323, self.fingerprint,
                                or_addresses=self.or_addresses)
        bridgeLine = bridge.getConfigLine()
        ip = bridgeLine.split(':')[0]
        self.assertTrue(ipaddr.IPAddress(ip))

    def test_integration_getConfigLine_vanilla_withFingerprint(self):
        """Should return a config line with a fingerprint."""
        bridge = bridges.Bridge('fpr', '23.23.23.23', 2323,
                                id_digest=self.id_digest,
                                or_addresses=self.or_addresses)
        bridgeLine = bridge.getConfigLine(includeFingerprint=True)
        self.assertSubstring(self.fingerprint, bridgeLine)
        ip = bridgeLine.split(':')[0]
        self.assertTrue(ipaddr.IPAddress(ip))

    def test_integration_getConfigLine_scramblesuit_withFingerprint(self):
        """Should return a scramblesuit config line with a fingerprint."""
        bridge = bridges.Bridge('philipkdick', '23.23.23.23', 2323,
                                id_digest=self.id_digest,
                                or_addresses=self.or_addresses)
        ptArgs = {'password': 'NEQGQYLUMUQGK5TFOJ4XI2DJNZTS4LRO'}
        pt = bridges.PluggableTransport(bridge.fingerprint, 'scramblesuit',
                                        ipaddr.IPAddress('42.42.42.42'), 4242,
                                        ptArgs)
        bridge.transports.append(pt)
        bridgeLine = bridge.getConfigLine(includeFingerprint=True,
                                          transport='scramblesuit')
        ptArgsList = ' '.join(["{0}={1}".format(k,v) for k,v in ptArgs.items()])
        self.assertEqual("scramblesuit 42.42.42.42:4242 %s %s"
                         % (self.fingerprint, ptArgsList),
                         bridgeLine)

    def test_integration_getDescriptorDigests(self):
        raise unittest.SkipTest(
            ("The functions getDescriptorDigests() and getExtraInfoDigests() "
             "have not been refactored into the new bridgedb.bridges module "
             "because it's not clear yet if they're necessary. Skip these "
             "tests for now."))

        sha1hash = hashlib.sha1()
        ei_digest = 'abcdefghijklmno'

        test = "this is a test line\nFollowed by another\n"
        test += "extra-info-digest %s\n" % ei_digest
        sha1hash.update(test)
        digest = sha1hash.hexdigest()
        test += "-----BEGIN SIGNATURE-----\n"
        test += "This is a test line that should be skipped\n"
        test += "-----END SIGNATURE-----\n"
        digests = bridges.getDescriptorDigests(io.StringIO(test))
        self.failUnlessIn(digest, digests)
        self.failUnlessEqual(ei_digest, digests[digest])

    def test_integration_getExtraInfoDigests(self):
        raise unittest.SkipTest(
            ("The functions getDescriptorDigests() and getExtraInfoDigests() "
             "have not been refactored into the new bridgedb.bridges module "
             "because it's not clear yet if they're necessary. Skip these "
             "tests for now."))

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
        digests = bridges.getExtraInfoDigests(io.StringIO(test))
        self.failUnlessIn(digest, digests)
        self.failUnlessEqual(content, digests[digest].read())

    def test_integration_splitterBridgeInsertion(self):
        key = "Testing-Bridges-To-Rings"
        splitter = FilteredBridgeSplitter(key)

        bridge1 = bridges.Bridge('unamed1', '1.2.3.5', 9100,
                                 'a1cc8dfef1fa11af9c40af1054df9daf45250550')
        bridge1.setStatus(running = True)
        bridge2 = bridges.Bridge('unamed2', '1.2.3.4', 8080,
                                 'a1cc8dfef1fa11af9c40af1054df9daf45250551')
        bridge2.setStatus(running = True)
        bridge3 = bridges.Bridge('unamed3', '5.2.3.4', 8080,
                                 'b1cc8dfef1fa11af9c40af1054df9daf45250552')
        bridge3.setStatus(running = True)
        bridge4 = bridges.Bridge('unamed3', '5.2.3.4', 8080,
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


class FlagsTests(unittest.TestCase):
    """Tests for :class:`bridgedb.bridges.Flags`."""

    def setUp(self):
        self.flags = bridges.Flags()
        self._all_flag_names = ["fast", "guard", "running", "stable", "valid"]

    def test_init(self):
        """Upon initialisation, all flags should be ``False``."""
        for flag in self._all_flag_names:
            f = getattr(self.flags, flag, None)
            self.assertFalse(f, "%s should be False" % flag)

    def test_settingStable(self):
        """Setting the Stable flag to ``True`` should result in Flags.stable
        being ``True``.
        """
        self.flags.stable = True
        self.assertTrue(self.flags.stable, "The Stable flag should be True")

    def test_settingRunning(self):
        """Setting the Running flag to ``True`` should result in Flags.running
        being ``True``.
        """
        self.flags.running = True
        self.assertTrue(self.flags.running, "The Running flag should be True")

    def test_changingFlags(self):
        """Setting a flag and then unsetting it should result in it being
        ``True`` and then ``False``.
        """
        self.flags.valid = True
        self.assertTrue(self.flags.valid, "The Valid flag should be True")
        self.flags.valid = False
        self.assertFalse(self.flags.valid, "The Valid flag should be False")

    def test_update(self):
        """Test changing flags with the update() method."""
        self.flags.update(["Fast", "Stable"])
        self.assertTrue(self.flags.fast)
        self.assertTrue(self.flags.stable)


class PluggableTransportTests(unittest.TestCase):
    """Tests for :class:`bridgedb.bridges.PluggableTransport."""

    def setUp(self):
        self.fingerprint = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"

    def test_PluggableTransport_init_with_parameters(self):
        """Initialising a PluggableTransport with args should work."""
        pt = bridges.PluggableTransport(self.fingerprint,
                                        "voltronPT", "1.2.3.4", 443,
                                        {'sharedsecret': 'foobar'})
        self.assertIsInstance(pt, bridges.PluggableTransport)

    def test_PluggableTransport_init(self):
        """Initialising a PluggableTransport without args should work."""
        pt = bridges.PluggableTransport()
        self.assertIsInstance(pt, bridges.PluggableTransport)

    def test_PluggableTransport_parseArgumentsIntoDict_valid_list(self):
        """Parsing a valid list of PT args should return a dictionary."""
        pt = bridges.PluggableTransport()
        args = pt._parseArgumentsIntoDict(["sharedsecret=foobar",
                                           "publickey=1234"])
        self.assertIsInstance(args, dict)
        self.assertItemsEqual(args, {"sharedsecret": "foobar",
                                     "publickey": "1234"})

    def test_PluggableTransport_parseArgumentsIntoDict_valid_list_multi(self):
        """Parsing a valid list with multiple PT args in a single list element
        should return a dictionary.
        """
        pt = bridges.PluggableTransport()
        args = pt._parseArgumentsIntoDict(["sharedsecret=foobar,password=baz",
                                           "publickey=1234"])
        self.assertIsInstance(args, dict)
        self.assertItemsEqual(args, {"sharedsecret": "foobar",
                                     "password": "baz",
                                     "publickey": "1234"})

    def test_PluggableTransport_parseArgumentsIntoDict_invalid_missing_equals(self):
        """Parsing a string of PT args where one PT arg (K=V) is missing an
        ``=`` character should raise a ValueError.
        """
        pt = bridges.PluggableTransport()
        args = pt._parseArgumentsIntoDict(
            ["sharedsecret=foobar,password,publickey=1234"])
        self.assertItemsEqual(args, {"sharedsecret": "foobar",
                                     "publickey": "1234"})

    def test_PluggableTransport_runChecks_invalid_fingerprint(self):
        """Calling _runChecks() on a PluggableTransport with an invalid
        fingerprint should raise a MalformedPluggableTransport exception.
        """
        pt = bridges.PluggableTransport()
        self.assertRaises(
            bridges.MalformedPluggableTransport,
            pt.updateFromStemTransport,
            "INVALIDFINGERPRINT", 'obfs4', ('34.230.223.87', 37341, [
                ('iat-mode=0,'
                 'node-id=2a79f14120945873482b7823caabe2fcde848722,'
                 'public-key=0a5b046d07f6f971b7776de682f57c5b9cdc8fa060db7ef59de82e721c8098f4')]))

    def test_PluggableTransport_runChecks_invalid_ip(self):
        """Calling _runChecks() on a PluggableTransport with an invalid
        IP address should raise a InvalidPluggableTransportIP exception.
        """
        pt = bridges.PluggableTransport()
        self.assertRaises(
            bridges.InvalidPluggableTransportIP,
            pt.updateFromStemTransport,
            self.fingerprint, 'obfs4', ('34.230.223', 37341, [
                ('iat-mode=0,'
                 'node-id=2a79f14120945873482b7823caabe2fcde848722,')]))

    def test_PluggableTransport_runChecks_invalid_port_type(self):
        """Calling _runChecks() on a PluggableTransport with an invalid port
        should raise a MalformedPluggableTransport exception.
        """
        pt = bridges.PluggableTransport()
        self.assertRaises(
            bridges.MalformedPluggableTransport,
            pt.updateFromStemTransport,
            self.fingerprint, 'obfs4', ('34.230.223.87', "anyport", [
                ('iat-mode=0,'
                 'node-id=2a79f14120945873482b7823caabe2fcde848722,')]))

    def test_PluggableTransport_runChecks_invalid_port_range(self):
        """Calling _runChecks() on a PluggableTransport with an invalid port
        (too high) should raise a MalformedPluggableTransport exception.
        """
        pt = bridges.PluggableTransport()
        self.assertRaises(
            bridges.MalformedPluggableTransport,
            pt.updateFromStemTransport,
            self.fingerprint, 'obfs4', ('34.230.223.87', 65536, [
                ('iat-mode=0,'
                 'node-id=2a79f14120945873482b7823caabe2fcde848722,')]))

    def test_PluggableTransport_runChecks_invalid_pt_args(self):
        """Calling _runChecks() on a PluggableTransport with an invalid PT
        args should raise a MalformedPluggableTransport exception.
        """
        try:
            pt = bridges.PluggableTransport(self.fingerprint,
                                            "voltronPT", "1.2.3.4", 443,
                                            'sharedsecret=foobar')
        except Exception as error:
            self.failUnlessIsInstance(error,
                                      bridges.MalformedPluggableTransport)

    def test_PluggableTransport_getTransportLine_bridge_prefix(self):
        """If the 'Bridge ' prefix was requested, then it should be at the
        beginning of the bridge line.
        """
        pt = bridges.PluggableTransport(self.fingerprint,
                                        "voltronPT", "1.2.3.4", 443,
                                        {'sharedsecret': 'foobar',
                                         'password': 'unicorns'})
        bridgeLine = pt.getTransportLine(bridgePrefix=True)
        self.assertTrue(bridgeLine.startswith("Bridge "))

    def test_PluggableTransport_getTransportLine_without_Fingerprint(self):
        """If no fingerprint was requested, then there shouldn't be a
        fingerprint in the bridge line.
        """
        pt = bridges.PluggableTransport(self.fingerprint,
                                        "voltronPT", "1.2.3.4", 443,
                                        {'sharedsecret': 'foobar',
                                         'password': 'unicorns'})
        bridgeLine = pt.getTransportLine(includeFingerprint=False)
        self.assertNotSubstring(self.fingerprint, bridgeLine)

    def test_PluggableTransport_getTransportLine_content_order(self):
        """Check the order and content of the bridge line string."""
        pt = bridges.PluggableTransport(self.fingerprint,
                                        "voltronPT", "1.2.3.4", 443,
                                        {'sharedsecret': 'foobar',
                                         'password': 'unicorns'})
        bridgeLine = pt.getTransportLine()

        # We have to check for substrings because we don't know which order
        # the PT arguments will end up in the bridge line.  Fortunately, the
        # following three are the only ones which are important to have in
        # order:
        self.assertTrue(bridgeLine.startswith("voltronPT"))
        self.assertSubstring("voltronPT 1.2.3.4:443 " + self.fingerprint,
                             bridgeLine)
        # These ones can be in any order, but they should be at the end of the
        # bridge line:
        self.assertSubstring("password=unicorns", bridgeLine)
        self.assertSubstring("sharedsecret=foobar", bridgeLine)

    def test_PluggableTransport_getTransportLine_ptargs_space_delimited(self):
        """The PT arguments in a bridge line should be space-separated."""
        pt = bridges.PluggableTransport(self.fingerprint,
                                        "voltronPT", "1.2.3.4", 443,
                                        {'sharedsecret': 'foobar',
                                         'password': 'unicorns'})
        bridgeLine = pt.getTransportLine()
        self.assertTrue(
            ("password=unicorns sharedsecret=foobar" in bridgeLine) or
            ("sharedsecret=foobar password=unicorns" in bridgeLine))
