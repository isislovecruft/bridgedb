# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2015, The Tor Project, Inc.
#             (c) 2007-2015, all entities within the AUTHORS file
# :license: 3-Clause BSD, see LICENSE for licensing information

"""Unittests for the :mod:`bridgedb.bridges` module."""

from binascii import a2b_hex

import datetime
import ipaddr
import io
import hashlib
import os
import warnings

from twisted.trial import unittest

from bridgedb import bridges
from bridgedb.Bridges import FilteredBridgeSplitter
from bridgedb.bridgerequest import BridgeRequestBase
from bridgedb.parse import descriptors
from bridgedb.parse.addr import PortList
from bridgedb.parse.nickname import InvalidRouterNickname


# Don't print "WARNING:root: Couldn't parse K=V from PT arg: ''" a bunch of
# times while running the tests.
warnings.filterwarnings("ignore", ".*Couldn't parse K=V from PT arg.*", Warning)


BRIDGE_NETWORKSTATUS = '''\
r FourfoldQuirked LDIlxIBTMQJeIR9Lblv0XDM/3Sw c4EVu2rO/iD/DJYBX/Ll38DGQWI 2014-12-22 21:51:27 179.178.155.140 36489 0
a [6bf3:806b:78cd:d4b4:f6a7:4ced:cfad:dad4]:36488
s Fast Guard Running Stable Valid
w Bandwidth=1585163
p reject 1-65535
'''

BRIDGE_SERVER_DESCRIPTOR = '''\
@purpose bridge
router FourfoldQuirked 179.178.155.140 36489 0 0
or-address [6bf3:806b:78cd:d4b4:f6a7:4ced:cfad:dad4]:36488
platform Tor 0.2.3.24-rc on Linux
opt protocols Link 1 2 Circuit 1
published 2014-12-22 21:51:27
opt fingerprint 2C32 25C4 8053 3102 5E21 1F4B 6E5B F45C 333F DD2C
uptime 33200687
bandwidth 1866688205 2110169275 1623207134
opt extra-info-digest 4497E81715D958105C6A39D348163AD8F3080FB2
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBANKicvIGWp9WGKOJV8Fs3YKdTDrgxlggzyKgkW+MZWEPQ9lLcrmXqBdW
nVK5EABByHnnxJfk+sm+6yDYxY/lFVL1SEP84pAK1Z21f4+grNlwox1DLyntXDdz
BCZuRszuBYK3ncsk+ePQeUzRKQ/GZt9s/oy0IjtNbAoAoq7DKUVzAgMBAAE=
-----END RSA PUBLIC KEY-----
signing-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALnJK7A9aZIp2ry9ruVYzm4VfaXzNHdTcvkXTrETu/jLXsosEwj9viSe
Ry3W/uctbjzdwlIY0ZBUuV20q9bh+/c7Q0T8LOHBZouOy+nhFOUX+Q5YCG9cRnY0
hBebYTzyplh0tT8xyYwcS8y6esL+gjVDLo6Og3QPhWRFQ4CyCic9AgMBAAE=
-----END RSA PUBLIC KEY-----
contact Somebody <somebody@example.com>
ntor-onion-key aVmfOm9C046wM8ktGnpfBHSNj1Jm30M/m2P7W3a7Xn8
reject *:*
router-signature
-----BEGIN SIGNATURE-----
nxml4rTyTrj8dHcsFt2B4ACz2AN5CuZ2t5UF1BtXUpuzHmqVlg7imy8Cp2xIwoDa
4uv/tTG32macauVnMHt0hSbtBF5nHfxU9G1T/XzdtL+KD8REDGky4allXnmvF6In
rFtSn2OeZewvi8oYPmVYKgzHL6tzZxs2Sn/bOTj5sRw=
-----END SIGNATURE-----
'''

BRIDGE_EXTRAINFO = '''\
extra-info FourfoldQuirked 2C3225C4805331025E211F4B6E5BF45C333FDD2C
published 2014-12-22 21:51:27
write-history 2014-12-22 21:51:27 (900 s) 3188736,2226176,2866176
read-history 2014-12-22 21:51:27 (900 s) 3891200,2483200,2698240
dirreq-write-history 2014-12-22 21:51:27 (900 s) 1024,0,2048
dirreq-read-history 2014-12-22 21:51:27 (900 s) 0,0,0
geoip-db-digest 51AE9611B53880B2BCF9C71E735D73F33FAD2DFE
geoip6-db-digest 26B0D55B20BEB496A3ADE7C6FDD866F5A81027F7
dirreq-stats-end 2014-12-22 21:51:27 (86400 s)
dirreq-v3-ips
dirreq-v3-reqs
dirreq-v3-resp ok=16,not-enough-sigs=0,unavailable=0,not-found=0,not-modified=0,busy=0
dirreq-v3-direct-dl complete=0,timeout=0,running=0
dirreq-v3-tunneled-dl complete=12,timeout=0,running=0
transport obfs3 179.178.155.140:36490
transport obfs2 179.178.155.140:36491
transport scramblesuit 179.178.155.140:36492 password=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
transport obfs4 179.178.155.140:36493 iat-mode=0,node-id=25293f2761d658cc70c19515861842d712751bdc,public-key=02d20bbd7e394ad5999a4cebabac9619732c343a4cac99470c03e23ba2bdc2bc
bridge-stats-end 2014-12-22 21:51:27 (86400 s)
bridge-ips ca=8
bridge-ip-versions v4=8,v6=0
bridge-ip-transports <OR>=8
router-signature
-----BEGIN SIGNATURE-----
cn4+8pQwCMPnHcp1s8wm7ZYsnd9AXJH6ysNlvQ63jsPCG9JdE5E8BwCThEgUccJI
XILT4o+SveEQUG72R4bENsKxqV4rRNh1g6CNAbYhAITqrU9B+jImDgrBBW+XWT5K
78ECRPn6Y4KsxFb0TIn7ddv9QjApyBJNIDMihH80Yng=
-----END SIGNATURE-----
'''


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
    test_splitterBridgeInsertion                    test_integration_splitterBridgeInsertion
    ==============================================  ========================
    ..
    """

    def setUp(self):
        self.nickname = 'unnamed'
        self.ip = ipaddr.IPAddress('127.0.0.1')
        self.orport = '9001'
        self.fingerprint = 'A1CC8DFEF1FA11AF9C40AF1054DF9DAF45250556'
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
        self.assertIsNotNone(bridgeLine)
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

    def test_update_Fast_Stable(self):
        """Test changing flags with the update() method."""
        self.flags.update(["Fast", "Stable"])
        self.assertTrue(self.flags.fast)
        self.assertTrue(self.flags.stable)

    def test_update_Fast(self):
        """Test changing flags with the update() method."""
        self.flags.update(["Fast"])
        self.assertTrue(self.flags.fast)
        self.assertFalse(self.flags.stable)

    def test_update_Stable(self):
        """Test changing flags with the update() method."""
        self.flags.update(["Stable"])
        self.assertFalse(self.flags.fast)
        self.assertTrue(self.flags.stable)


class BridgeAddressBaseTests(unittest.TestCase):
    """Tests for :class:`bridgedb.bridges.BridgeAddressBase`."""

    def setUp(self):
        self.fingerprint = '2C3225C4805331025E211F4B6E5BF45C333FDD2C'
        self.bab = bridges.BridgeAddressBase()

    def test_BridgeAddressBase_init(self):
        """The BridgeAddressBase's _address and _fingerprint should be None."""
        self.assertIsNone(self.bab._address)
        self.assertIsNone(self.bab._fingerprint)

    def test_BridgeAddressBase_fingerprint_del(self):
        """The del method for the fingerprint property should reset the
        fingerprint to None.
        """
        self.bab.fingerprint = self.fingerprint
        self.assertEqual(self.bab.fingerprint, self.fingerprint)

        del(self.bab.fingerprint)
        self.assertIsNone(self.bab.fingerprint)
        self.assertIsNone(self.bab._fingerprint)

    def test_BridgeAddressBase_address_del(self):
        """The del method for the address property should reset the
        address to None.
        """
        self.bab.address = '11.12.13.14'
        self.assertEqual(self.bab.address, ipaddr.IPv4Address('11.12.13.14'))

        del(self.bab.address)
        self.assertIsNone(self.bab.address)
        self.assertIsNone(self.bab._address)

    def test_BridgeAddressBase_country(self):
        """The getter method for the country property should get the
        address's geoIP country code.
        """
        self.bab.address = '11.12.13.14'
        self.assertEqual(self.bab.address, ipaddr.IPv4Address('11.12.13.14'))

        cc = self.bab.country
        self.assertIsNotNone(cc)
        self.assertIsInstance(cc, basestring)
        self.assertEqual(len(cc), 2)


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

    def test_PluggableTransport_port_del(self):
        """The del method for the port property should reset the port to None.
        """
        pt = bridges.PluggableTransport(self.fingerprint,
                                        "voltronPT", "1.2.3.4", 443,
                                        {'sharedsecret': 'foobar'})
        self.assertEqual(pt.port, 443)

        del(pt.port)
        self.assertIsNone(pt.port)
        self.assertIsNone(pt._port)

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

    def test_PluggableTransport_getTransportLine_IPv6(self):
        """The address portion of a bridge line with an IPv6 address should
        have square brackets around it.
        """
        pt = bridges.PluggableTransport(self.fingerprint,
                                        "voltronPT", "2006:42::1234", 443,
                                        {'sharedsecret': 'foobar',
                                         'password': 'unicorns'})
        bridgeLine = pt.getTransportLine()
        self.assertEqual(pt.address.version, 6)
        self.assertIn("[2006:42::1234]:443", bridgeLine)


class BridgeBackwardsCompatibilityTests(unittest.TestCase):
    """Tests for :class:`bridgedb.bridges.BridgeBackwardsCompatibility`."""

    def setUp(self):
        self.nickname = "RouterNickname"
        self.address = "23.23.23.23"
        self.orPort = 9001
        self.fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567"
        self.orAddresses = {"2006:42::123F": PortList(443, 9001, 1337),
                            "2006:42::123E": PortList(9001, 993)}

    def test_BridgeBackwardsCompatibility_init_with_PortList(self):
        """Test initialisation with the usual number of valid arguments and
        PortLists for the orAddresses.
        """
        bridge = bridges.BridgeBackwardsCompatibility(
            self.nickname,
            self.address,
            self.orPort,
            self.fingerprint,
            self.orAddresses)
        self.assertIsInstance(bridge, bridges.BridgeBackwardsCompatibility)

    def test_BridgeBackwardsCompatibility_init_without_PortList(self):
        """Test initialisation with the usual number of valid arguments and
        integers for the orAddresses' ports.
        """
        bridge = bridges.BridgeBackwardsCompatibility(
            self.nickname,
            self.address,
            self.orPort,
            self.fingerprint,
            {"2006:42::123F": 443,
             "2006:42::123E": 9001})
        self.assertIsInstance(bridge, bridges.BridgeBackwardsCompatibility)

    def test_BridgeBackwardsCompatibility_init_without_address(self):
        """Test initialisation without an IP address."""
        bridge = bridges.BridgeBackwardsCompatibility(
            nickname=self.nickname,
            orport=self.orPort,
            fingerprint=self.fingerprint,
            or_addresses={"2006:42::123F": 443, "2006:42::123E": 9001})
        self.assertIsInstance(bridge, bridges.BridgeBackwardsCompatibility)

    def test_BridgeBackwardsCompatibility_init_invalid_orAddresses_address(self):
        """Test initialisation with an invalid ORAddress."""
        bridge = bridges.BridgeBackwardsCompatibility(
            nickname=self.nickname,
            ip=self.address,
            orport=self.orPort,
            fingerprint=self.fingerprint,
            or_addresses={"10.1.2.3": 443, "2006:42::123E": 9001})
        self.assertIsInstance(bridge, bridges.BridgeBackwardsCompatibility)
        self.assertEqual(len(bridge.orAddresses), 1)

    def test_BridgeBackwardsCompatibility_init_invalid_orAddresses_port(self):
        """Test initialisation with an invalid ORPort."""
        bridge = bridges.BridgeBackwardsCompatibility(
            nickname=self.nickname,
            ip=self.address,
            orport=self.orPort,
            fingerprint=self.fingerprint,
            or_addresses={"2006:42::123F": 443, "2006:42::123E": "anyport"})
        self.assertIsInstance(bridge, bridges.BridgeBackwardsCompatibility)
        self.assertEqual(len(bridge.orAddresses), 1)

    def test_BridgeBackwardsCompatibility_setStatus_running(self):
        """Using setStatus() to set the Running flag should set Bridge.running
        and Bridge.flags.running to True.
        """
        bridge = bridges.BridgeBackwardsCompatibility(
            nickname=self.nickname,
            ip=self.address,
            orport="anyport",
            fingerprint=self.fingerprint,
            or_addresses={"2006:42::123F": 443, "2006:42::123E": 9001})
        self.assertIsInstance(bridge, bridges.BridgeBackwardsCompatibility)
        self.assertFalse(bridge.running)
        self.assertFalse(bridge.flags.running)

        bridge.setStatus(running=True)
        self.assertTrue(bridge.running)
        self.assertTrue(bridge.flags.running)

    def test_BridgeBackwardsCompatibility_setStatus_running(self):
        """Using setStatus() to set the Running and Stable flags should set
        Bridge.running, Bridge.flags.running, Bridge.stable, and
        Bridge.flags.stable.
        """
        bridge = bridges.BridgeBackwardsCompatibility(
            nickname=self.nickname,
            ip=self.address,
            orport="anyport",
            fingerprint=self.fingerprint,
            or_addresses={"2006:42::123F": 443, "2006:42::123E": 9001})
        self.assertIsInstance(bridge, bridges.BridgeBackwardsCompatibility)
        self.assertFalse(bridge.running)
        self.assertFalse(bridge.flags.running)
        self.assertFalse(bridge.stable)
        self.assertFalse(bridge.flags.stable)

        bridge.setStatus(running=True, stable=True)
        self.assertTrue(bridge.running)
        self.assertTrue(bridge.flags.running)
        self.assertTrue(bridge.stable)
        self.assertTrue(bridge.flags.stable)


class BridgeTests(unittest.TestCase):
    """Tests for :class:`bridgedb.bridges.Bridge`."""

    def _parseAllDescriptorFiles(self):
        self.networkstatus = descriptors.parseNetworkStatusFile(
            self._networkstatusFile)[0]
        self.serverdescriptor = descriptors.parseServerDescriptorsFile(
            self._serverDescriptorFile)[0]
        self.extrainfo = descriptors.parseExtraInfoFiles(
            self._extrainfoFile).values()[0]

    def _writeNetworkstatus(self, networkstatus):
        with open(self._networkstatusFile, 'w') as fh:
            fh.write(networkstatus)
            fh.flush()

    def _writeServerdesc(self, serverdesc):
        with open(self._serverDescriptorFile, 'w') as fh:
            fh.write(serverdesc)
            fh.flush()

    def _writeExtrainfo(self, extrainfo):
        with open(self._extrainfoFile, 'w') as fh:
            fh.write(extrainfo)
            fh.flush()

    def _writeDescriptorFiles(self, networkstatus, serverdesc, extrainfo):
        self._writeNetworkstatus(networkstatus)
        self._writeServerdesc(serverdesc)
        self._writeExtrainfo(extrainfo)

    def setUp(self):
        def _cwd(filename):
            return os.path.sep.join([os.getcwd(), filename])

        self._networkstatusFile = _cwd('BridgeTests-networkstatus-bridges')
        self._serverDescriptorFile = _cwd('BridgeTests-bridge-descriptors')
        self._extrainfoFile = _cwd('BridgeTests-cached-extrainfo')

        self._writeDescriptorFiles(BRIDGE_NETWORKSTATUS,
                                   BRIDGE_SERVER_DESCRIPTOR,
                                   BRIDGE_EXTRAINFO)
        self._parseAllDescriptorFiles()

        self.bridge = bridges.Bridge()

    def tearDown(self):
        """Reset safelogging to its default (disabled) state, due to
        test_Bridge_str_with_safelogging changing it.
        """
        bridges.safelog.safe_logging = False

    def test_Bridge_nickname_del(self):
        """The del method for the nickname property should reset the nickname
        to None.
        """
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.assertEqual(self.bridge.nickname, "FourfoldQuirked")

        del(self.bridge.nickname)
        self.assertIsNone(self.bridge.nickname)
        self.assertIsNone(self.bridge._nickname)

    def test_Bridge_nickname_invalid(self):
        """The del method for the nickname property should reset the nickname
        to None.
        """
        # Create a networkstatus descriptor with an invalid nickname:
        filename = self._networkstatusFile + "-invalid"
        fh = open(filename, 'w')
        invalid = BRIDGE_NETWORKSTATUS.replace(
            "FourfoldQuirked",
            "ThisRouterNicknameContainsWayMoreThanNineteenBytes")
        fh.seek(0)
        fh.write(invalid)
        fh.flush()
        fh.close()

        self.assertRaises(InvalidRouterNickname,
                          descriptors.parseNetworkStatusFile,
                          filename)

    def test_Bridge_orport_del(self):
        """The del method for the orPort property should reset the orPort
        to None.
        """
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.assertEqual(self.bridge.orPort, 36489)

        del(self.bridge.orPort)
        self.assertIsNone(self.bridge.orPort)
        self.assertIsNone(self.bridge._orPort)

    def test_Bridge_str_without_safelogging(self):
        """The str() method of a Bridge should return an identifier for the
        Bridge, which should be different if safelogging is enabled.
        """
        bridges.safelog.safe_logging = False

        bridge = bridges.Bridge()
        bridge.updateFromNetworkStatus(self.networkstatus)

        identifier = str(bridge)
        self.assertEqual(identifier,
                         ''.join(['$', bridge.fingerprint,
                                  '~', bridge.nickname]))

    def test_Bridge_str_with_safelogging(self):
        """The str() method of a Bridge should return an identifier for the
        Bridge, which should be different if safelogging is enabled.
        """
        bridges.safelog.safe_logging = True

        bridge = bridges.Bridge()
        bridge.updateFromNetworkStatus(self.networkstatus)

        identifier = str(bridge)
        self.assertEqual(
            identifier,
            ''.join(['$$',
                     hashlib.sha1(bridge.fingerprint).hexdigest().upper(),
                     '~', bridge.nickname]))

    def test_Bridge_str_without_fingerprint(self):
        """The str() method of a Bridge should return an identifier for the
        Bridge, which should be different if the fingerprint is unknown.
        """
        bridge = bridges.Bridge()
        bridge.updateFromNetworkStatus(self.networkstatus)
        del(bridge.fingerprint)

        identifier = str(bridge)
        self.assertEqual(identifier,
                         ''.join(['$', '0'*40,
                                  '~', bridge.nickname]))

    def test_Bridge_updateFromNetworkStatus_IPv4_ORAddress(self):
        """Calling updateFromNetworkStatus() with a descriptor which has an
        IPv4 address as an additional ORAddress should result in a
        FutureWarning before continuing parsing.
        """
        # Add an additional IPv4 ORAddress:
        ns = BRIDGE_NETWORKSTATUS.replace(
            'a [6bf3:806b:78cd:d4b4:f6a7:4ced:cfad:dad4]:36488',
            'a [6bf3:806b:78cd:d4b4:f6a7:4ced:cfad:dad4]:36488\na 123.34.56.78:36488')
        self._writeNetworkstatus(ns)
        self._parseAllDescriptorFiles()

        self.assertWarns(
            FutureWarning,
            "Got IPv4 address in 'a'/'or-address' line! Descriptor format may have changed!",
            bridges.__file__,  # filename
            self.bridge.updateFromNetworkStatus,
            self.networkstatus)

        self.assertEqual(self.bridge.fingerprint,
                         '2C3225C4805331025E211F4B6E5BF45C333FDD2C')
        self.assertIn((ipaddr.IPAddress('123.34.56.78'), 36488, 4),
                      self.bridge.allVanillaAddresses)

    def test_Bridge_updateFromServerDescriptor(self):
        """ """
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.bridge.updateFromServerDescriptor(self.serverdescriptor)

        self.assertEqual(self.bridge.fingerprint,
                         '2C3225C4805331025E211F4B6E5BF45C333FDD2C')

    def test_Bridge_updateFromServerDescriptor_no_networkstatus(self):
        """Parsing a server descriptor for a bridge which wasn't included in
        the networkstatus document from the BridgeAuthority should raise a
        ServerDescriptorWithoutNetworkstatus exception.
        """
        self.assertRaises(bridges.ServerDescriptorWithoutNetworkstatus,
                          self.bridge.updateFromServerDescriptor,
                          self.serverdescriptor)

    def test_Bridge_verifyExtraInfoSignature_good_signature(self):
        """Calling _verifyExtraInfoSignature() with a descriptor which has a
        good signature should return None.
        """
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.bridge.updateFromServerDescriptor(self.serverdescriptor)
        self.assertIsNone(self.bridge._verifyExtraInfoSignature(self.extrainfo))

    def test_Bridge_updateFromExtraInfoDescriptor(self):
        """Bridge.updateFromExtraInfoDescriptor() should add the expected
        number of pluggable transports.
        """
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.assertEqual(self.bridge.fingerprint,
                         '2C3225C4805331025E211F4B6E5BF45C333FDD2C')
        self.assertEqual(self.bridge.bandwidthObserved, None)
        self.assertEqual(len(self.bridge.transports), 0)

        self.bridge.updateFromServerDescriptor(self.serverdescriptor)
        self.assertEqual(self.bridge.fingerprint,
                         '2C3225C4805331025E211F4B6E5BF45C333FDD2C')
        self.assertEqual(self.bridge.bandwidthObserved, 1623207134)
        self.assertEqual(len(self.bridge.transports), 0)

        self.bridge.updateFromExtraInfoDescriptor(self.extrainfo)
        self.assertEqual(self.bridge.fingerprint,
                         '2C3225C4805331025E211F4B6E5BF45C333FDD2C')
        self.assertEqual(self.bridge.bandwidthObserved, 1623207134)
        self.assertEqual(len(self.bridge.transports), 4)

    def test_Bridge_updateFromExtraInfoDescriptor_bad_signature_changed(self):
        """Calling updateFromExtraInfoDescriptor() with a descriptor which
        has a bad signature should not continue to process the descriptor.
        """
        # Make the signature uppercased
        BEGIN_SIG = '-----BEGIN SIGNATURE-----'
        doc, sig = BRIDGE_EXTRAINFO.split(BEGIN_SIG)
        ei = BEGIN_SIG.join([doc, sig.upper()])
        self._writeExtrainfo(ei)
        self._parseAllDescriptorFiles()

        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.bridge.updateFromServerDescriptor(self.serverdescriptor)
        self.bridge.updateFromExtraInfoDescriptor(self.extrainfo)

        self.assertEqual(len(self.bridge.transports), 0)
        self.assertIsNone(self.bridge.descriptors['extrainfo'])

    def test_Bridge_updateFromExtraInfoDescriptor_pt_changed_port(self):
        """Calling updateFromExtraInfoDescriptor() with a descriptor which
        includes a different port for a known bridge with a known pluggable
        transport should update that transport.
        """
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.bridge.updateFromServerDescriptor(self.serverdescriptor)
        self.bridge.updateFromExtraInfoDescriptor(self.extrainfo)

        self.assertEqual(len(self.bridge.transports), 4)

        for pt in self.bridge.transports:
            if pt.methodname == 'obfs4':
                self.assertEqual(pt.address, ipaddr.IPv4Address('179.178.155.140'))
                self.assertEqual(pt.port, 36493)

        # Change the port of obfs4 transport in the extrainfo descriptor:
        transportline = self.extrainfo.transport['obfs4']
        self.extrainfo.transport['obfs4'] = (transportline[0],
                                             31337,
                                             transportline[2])
        self.bridge.updateFromExtraInfoDescriptor(self.extrainfo)

        for pt in self.bridge.transports:
            if pt.methodname == 'obfs4':
                self.assertEqual(pt.address, ipaddr.IPv4Address('179.178.155.140'))
                self.assertEqual(pt.port, 31337)

    def test_Bridge_updateFromExtraInfoDescriptor_pt_changed_args(self):
        """Calling updateFromExtraInfoDescriptor() with a descriptor which
        includes different PT args for a known bridge with a known pluggable
        transport should update that transport.

        scramblesuit 179.178.155.140:36492 password=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
        """
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.bridge.updateFromServerDescriptor(self.serverdescriptor)
        self.bridge.updateFromExtraInfoDescriptor(self.extrainfo)

        self.assertEqual(len(self.bridge.transports), 4)

        for pt in self.bridge.transports:
            if pt.methodname == 'scramblesuit':
                self.assertEqual(pt.address, ipaddr.IPv4Address('179.178.155.140'))
                self.assertEqual(pt.port, 36492)

        # Change the args of scramblesuit transport in the extrainfo descriptor:
        transportline = self.extrainfo.transport['scramblesuit']
        self.extrainfo.transport['scramblesuit'] = (transportline[0],
                                                    transportline[1],
                                                    ['password=PASSWORD'])
        self.bridge.updateFromExtraInfoDescriptor(self.extrainfo)

        for pt in self.bridge.transports:
            if pt.methodname == 'scramblesuit':
                self.assertEqual(pt.address, ipaddr.IPv4Address('179.178.155.140'))
                self.assertEqual(pt.port, 36492)
                self.assertEqual(pt.arguments['password'], 'PASSWORD')

    def test_Bridge_updateFromExtraInfoDescriptor_pt_died(self):
        """Calling updateFromExtraInfoDescriptor() with a descriptor which
        doesn't include a previously-known transport should remove that
        transport.
        """
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.bridge.updateFromServerDescriptor(self.serverdescriptor)
        self.bridge.updateFromExtraInfoDescriptor(self.extrainfo)

        self.assertEqual(len(self.bridge.transports), 4)

        # Remove the obfs3 transport from the extrainfo descriptor:
        self.extrainfo.transport.pop('obfs3')
        self.bridge.updateFromExtraInfoDescriptor(self.extrainfo)

        self.assertEqual(len(self.bridge.transports), 3)

        for pt in self.bridge.transports:
            self.failIfEqual(pt.methodname, 'obfs3')

    def test_Bridge_descriptorDigest(self):
        """Parsing a networkstatus descriptor should result in
        Bridge.descriptorDigest being set.
        """
        realdigest = "738115BB6ACEFE20FF0C96015FF2E5DFC0C64162"
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.assertEqual(self.bridge.descriptorDigest, realdigest)

    def test_Bridge_checkServerDescriptor(self):
        """Parsing a server descriptor when the bridge's networkstatus document
        didn't have a digest of the server descriptor should raise a
        MissingServerDescriptorDigest.
        """
        # Create a networkstatus descriptor without a server descriptor digest:
        filename = self._networkstatusFile + "-missing-digest"
        fh = open(filename, 'w')
        invalid = BRIDGE_NETWORKSTATUS.replace("c4EVu2rO/iD/DJYBX/Ll38DGQWI", "foo")
        fh.seek(0)
        fh.write(invalid)
        fh.flush()
        fh.close()

        realdigest = "738115BB6ACEFE20FF0C96015FF2E5DFC0C64162"

        #networkstatus = descriptors.parseNetworkStatusFile(filename)
        #self.bridge.updateFromNetworkStatus(networkstatus[0])
        #self.assertRaises(bridges.MissingServerDescriptorDigest,
        #                  self.bridge.updateFromNetworkStatus,
        #                  networkstatus[0])

    def test_Bridge_checkServerDescriptor_digest_mismatch_ns(self):
        """Parsing a server descriptor whose digest doesn't match the one given
        in the bridge's networkstatus document should raise a
        ServerDescriptorDigestMismatch.
        """
        # Create a networkstatus descriptor without a server descriptor digest:
        filename = self._networkstatusFile + "-mismatched-digest"
        fh = open(filename, 'w')
        invalid = BRIDGE_NETWORKSTATUS.replace("c4EVu2rO/iD/DJYBX/Ll38DGQWI",
                                               "c4EVu2r1/iD/DJYBX/Ll38DGQWI")
        fh.seek(0)
        fh.write(invalid)
        fh.flush()
        fh.close()

        realdigest = "738115BB6ACEFE20FF0C96015FF2E5DFC0C64162"
        networkstatus = descriptors.parseNetworkStatusFile(filename)
        self.bridge.updateFromNetworkStatus(networkstatus[0])
        #self.bridge.updateFromServerDescriptor(self.serverdescriptor)

        self.assertRaises(bridges.ServerDescriptorDigestMismatch,
                          self.bridge.updateFromServerDescriptor,
                          self.serverdescriptor)

    def test_Bridge_checkServerDescriptor_digest_mismatch_sd(self):
        """Parsing a server descriptor when the corresponding networkstatus
        descriptor didn't include a server bridge.descriptorDigest that matches
        should raise a ServerDescriptorDigestMismatch exception.
        """
        self.bridge.updateFromNetworkStatus(self.networkstatus)

        self.bridge.descriptorDigest = 'deadbeef'
        self.assertRaises(bridges.ServerDescriptorDigestMismatch,
                          self.bridge._checkServerDescriptor,
                          self.serverdescriptor)

    def test_Bridge_checkServerDescriptor_digest_missing(self):
        """Parsing a server descriptor when the corresponding networkstatus
        descriptor didn't include a server bridge.descriptorDigest should raise
        a MissingServerDescriptorDigest exception.
        """
        self.bridge.updateFromNetworkStatus(self.networkstatus)

        self.bridge.descriptorDigest = None
        self.assertRaises(bridges.MissingServerDescriptorDigest,
                          self.bridge._checkServerDescriptor,
                          self.serverdescriptor)

    def test_Bridge_assertOK(self):
        """If all orAddresses are okay, then assertOK() should return None."""
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.bridge.updateFromServerDescriptor(self.serverdescriptor)

        self.assertIsNone(self.bridge.assertOK())

    def test_Bridge_assertOK_all_bad_values(self):
        """If an orAddress has an IP address of 999.999.999.999 and a port of
        -1 and claims to be IPv5, then everything about it is bad and it should
        fail all the checks in assertOK(), then a MalformedBridgeInfo should be
        raised.
        """
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.bridge.updateFromServerDescriptor(self.serverdescriptor)

        # All values are bad (even though IPv5 is a thing):
        self.bridge.orAddresses.append(('999.999.999.999', -1, 5))
        self.assertRaises(bridges.MalformedBridgeInfo, self.bridge.assertOK)

    def test_Bridge_getBridgeLine_request_valid(self):
        """Calling getBridgeLine with a valid request should return a bridge
        line.
        """
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.bridge.updateFromServerDescriptor(self.serverdescriptor)
        self.bridge.updateFromExtraInfoDescriptor(self.extrainfo)

        request = BridgeRequestBase()
        request.isValid(True)
        line = self.bridge.getBridgeLine(request)

        self.assertIsNotNone(line)
        self.assertIn('179.178.155.140:36489', line)
        self.assertIn('2C3225C4805331025E211F4B6E5BF45C333FDD2C', line)

    def test_Bridge_getBridgeLine_request_invalid(self):
        """Calling getBridgeLine with an invalid request should return None."""
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.bridge.updateFromServerDescriptor(self.serverdescriptor)
        self.bridge.updateFromExtraInfoDescriptor(self.extrainfo)

        request = BridgeRequestBase()
        request.isValid(False)

        self.assertIsNone(self.bridge.getBridgeLine(request))

    def test_Bridge_getBridgeLine_no_vanilla_addresses(self):
        """Calling getBridgeLine() on a Bridge without any vanilla addresses
        should return None.
        """
        request = BridgeRequestBase()
        request.isValid(True)

        self.assertIsNone(self.bridge.getBridgeLine(request))

    def test_Bridge_getBridgeLine_request_without_block_in_IR(self):
        """Calling getBridgeLine() with a valid request for bridges not blocked
        in Iran should return a bridge line.
        """
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.bridge.updateFromServerDescriptor(self.serverdescriptor)
        self.bridge.updateFromExtraInfoDescriptor(self.extrainfo)

        request = BridgeRequestBase()
        request.isValid(True)
        request.withoutBlockInCountry('IR')
        line = self.bridge.getBridgeLine(request)

        self.assertIsNotNone(line)
        self.assertIn('179.178.155.140:36489', line)
        self.assertIn('2C3225C4805331025E211F4B6E5BF45C333FDD2C', line)

    def test_Bridge_getBridgeLine_IPv6(self):
        """Calling getBridgeLine() with a valid request for IPv6 bridges
        should return a bridge line.
        """
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.bridge.updateFromServerDescriptor(self.serverdescriptor)
        self.bridge.updateFromExtraInfoDescriptor(self.extrainfo)

        request = BridgeRequestBase()
        request.isValid(True)
        request.withIPv6()
        line = self.bridge.getBridgeLine(request)

        self.assertIsNotNone(line)
        self.assertTrue(
            line.startswith('[6bf3:806b:78cd:d4b4:f6a7:4ced:cfad:dad4]:36488'))
        self.assertNotIn('179.178.155.140:36493', line)
        self.assertIn('2C3225C4805331025E211F4B6E5BF45C333FDD2C', line)

    def test_Bridge_getBridgeLine_obfs4(self):
        """ """
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.bridge.updateFromServerDescriptor(self.serverdescriptor)
        self.bridge.updateFromExtraInfoDescriptor(self.extrainfo)

        request = BridgeRequestBase()
        request.isValid(True)
        request.withPluggableTransportType('obfs4')
        line = self.bridge.getBridgeLine(request)

        self.assertIsNotNone(line)
        self.assertIn('179.178.155.140:36493', line)
        self.assertTrue(line.startswith('obfs4'))
        self.assertIn('iat-mode', line)
        self.assertIn('public-key', line)
        self.assertIn('node-id', line)

    def test_Bridge_getBridgeLine_obfs3_IPv6(self):
        """Calling getBridgeLine() with a request for IPv6 obfs3 bridges (when
        the Bridge doesn't have any) should raise a
        PluggableTransportUnavailable exception.
        """
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.bridge.updateFromServerDescriptor(self.serverdescriptor)
        self.bridge.updateFromExtraInfoDescriptor(self.extrainfo)

        request = BridgeRequestBase()
        request.isValid(True)
        request.withIPv6()
        request.withPluggableTransportType('obfs3')

        self.assertRaises(bridges.PluggableTransportUnavailable,
                          self.bridge.getBridgeLine,
                          request)

    def test_Bridge_getBridgeLine_googlygooglybegone(self):
        """Calling getBridgeLine() with a request for an unknown PT should
        raise a PluggableTransportUnavailable exception.
        """
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.bridge.updateFromServerDescriptor(self.serverdescriptor)
        self.bridge.updateFromExtraInfoDescriptor(self.extrainfo)

        request = BridgeRequestBase()
        request.isValid(True)
        request.withPluggableTransportType('googlygooglybegone')

        self.assertRaises(bridges.PluggableTransportUnavailable,
                          self.bridge.getBridgeLine,
                          request)

    def test_Bridge_getBridgeLine_bridge_prefix(self):
        """Calling getBridgeLine() with bridgePrefix=True should prefix the
        returned bridge line with 'Bridge '.
        """
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.bridge.updateFromServerDescriptor(self.serverdescriptor)
        self.bridge.updateFromExtraInfoDescriptor(self.extrainfo)

        request = BridgeRequestBase()
        request.isValid(True)
        line = self.bridge.getBridgeLine(request, bridgePrefix=True)

        self.assertIsNotNone(line)
        self.assertIn('179.178.155.140:36489', line)
        self.assertIn('2C3225C4805331025E211F4B6E5BF45C333FDD2C', line)
        self.assertTrue(line.startswith('Bridge'))

    def test_Bridge_getBridgeLine_no_include_fingerprint(self):
        """Calling getBridgeLine() with includeFingerprint=False should return
        a bridge line without a fingerprint.
        """
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.bridge.updateFromServerDescriptor(self.serverdescriptor)
        self.bridge.updateFromExtraInfoDescriptor(self.extrainfo)

        request = BridgeRequestBase()
        request.isValid(True)
        line = self.bridge.getBridgeLine(request, includeFingerprint=False)

        self.assertIsNotNone(line)
        self.assertIn('179.178.155.140:36489', line)
        self.assertNotIn('2C3225C4805331025E211F4B6E5BF45C333FDD2C', line)

    def test_Bridge_getNetworkstatusLastPublished(self):
        """Calling getNetworkstatusLastPublished() should tell us the last
        published time of the Bridge's server-descriptor.
        """
        self.bridge.updateFromNetworkStatus(self.networkstatus)

        published = self.bridge.getNetworkstatusLastPublished()
        self.assertIsNotNone(published)
        self.assertIsInstance(published, datetime.datetime)
        self.assertEqual(str(published), '2014-12-22 21:51:27')

    def test_Bridge_getDescriptorLastPublished(self):
        """Calling getDescriptorLastPublished() should tell us the last
        published time of the Bridge's server-descriptor.
        """
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.bridge.updateFromServerDescriptor(self.serverdescriptor)

        published = self.bridge.getDescriptorLastPublished()
        self.assertIsNotNone(published)
        self.assertIsInstance(published, datetime.datetime)
        self.assertEqual(str(published), '2014-12-22 21:51:27')

    def test_Bridge_getExtrainfoLastPublished(self):
        """Calling getNetworkstatusLastPublished() should tell us the last
        published time of the Bridge's server-descriptor.
        """
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.bridge.updateFromServerDescriptor(self.serverdescriptor)
        self.bridge.updateFromExtraInfoDescriptor(self.extrainfo)

        published = self.bridge.getExtrainfoLastPublished()
        self.assertIsNotNone(published)
        self.assertIsInstance(published, datetime.datetime)
        self.assertEqual(str(published), '2014-12-22 21:51:27')

    def test_Bridge_isBlockedIn_IS(self):
        """Calling isBlockedIn('IS') should return False when the bridge isn't
        blocked in Iceland.
        """
        self.assertFalse(self.bridge.isBlockedIn('IS'))

    def test_Bridge_setBlockedIn_CN_obfs2(self):
        """Calling setBlockedIn('CN', 'obfs2') should mark all obfs2 transports
        of the bridge as being blocked in CN.
        """
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.bridge.updateFromServerDescriptor(self.serverdescriptor)
        self.bridge.updateFromExtraInfoDescriptor(self.extrainfo)

        self.bridge.setBlockedIn('CN', methodname='obfs2')
        self.assertTrue(self.bridge.isBlockedIn('CN'))

    def test_Bridge_setBlockedIn_IR_address(self):
        """Calling setBlockedIn('IR', address) should mark all matching
        addresses of the bridge as being blocked in IR.
        """
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.bridge.updateFromServerDescriptor(self.serverdescriptor)
        self.bridge.updateFromExtraInfoDescriptor(self.extrainfo)

        self.bridge.setBlockedIn('IR', address='179.178.155.140')
        self.assertTrue(self.bridge.isBlockedIn('ir'))
        self.assertFalse(self.bridge.isBlockedIn('cn'))

    def test_Bridge_setBlockedIn_GB_address_port(self):
        """Calling setBlockedIn('GB', address, port) should mark all matching
        addresses:port pairs of the bridge as being blocked in GB.
        """
        self.bridge.updateFromNetworkStatus(self.networkstatus)
        self.bridge.updateFromServerDescriptor(self.serverdescriptor)
        self.bridge.updateFromExtraInfoDescriptor(self.extrainfo)

        # Should block the obfs4 bridge:
        self.bridge.setBlockedIn('GB', address='179.178.155.140', port=36493)
        self.assertTrue(self.bridge.isBlockedIn('GB'))
        self.assertTrue(self.bridge.isBlockedIn('gb'))
        self.assertTrue(self.bridge.transportIsBlockedIn('GB', 'obfs4'))
        self.assertTrue(self.bridge.addressIsBlockedIn('GB', '179.178.155.140', 36493))
        self.assertFalse(self.bridge.addressIsBlockedIn('gb', '179.178.155.140', 36488))
