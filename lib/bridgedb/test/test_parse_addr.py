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

"""Unittests for the :mod:`bridgedb.parse.addr` module.
"""

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import ipaddr
import random

from twisted.python import log
from twisted.trial import unittest

from bridgedb.parse import addr


IP4LinkLocal = "169.254.0.0"
IP6LinkLocal = "fe80::1234"
IP4Loopback = "127.0.0.0"
IP4Localhost = "127.0.0.1"
IP6Localhost = "::1"
IP4LimitedBroadcast = "255.255.255.0"
IP4Multicast_224 = "224.0.0.1"
IP4Multicast_239 = "239.0.0.1"
IP4Unspecified = "0.0.0.0"
IP6Unspecified = "::"
IP4DefaultRoute = "0.0.0.0"
IP6DefaultRoute = "::"
IP4ReservedRFC1918_10 = "10.0.0.0"
IP4ReservedRFC1918_172_16 = "172.16.0.0"
IP4ReservedRFC1918_192_168 = "192.168.0.0"
IP4ReservedRFC1700 = "240.0.0.0"
IP6UniqueLocal = "fc00::"
IP6SiteLocal = "fec0::"


class CanonicalizeEmailDomainTests(unittest.TestCase):
    """Unittests for :func:`bridgedb.parse.addr.canonicalizeEmailDomain`."""

    def test_nonDict(self):
        """Using a non-dict domainmap as a parameter to
        canonicalizeEmailDomain() should log an AttributeError and then raise
        an UnsupportedDomain error.
        """
        domainmap = 'example.com'
        domain = 'fubar.com'
        self.assertRaises(addr.UnsupportedDomain,
                          addr.canonicalizeEmailDomain,
                          domain, domainmap)

    def test_notPermitted(self):
        """A domain not in the domainmap of allowed domains should raise an
        UnsupportedDomain error.
        """
        domainmap = {'foo.example.com': 'example.com'}
        domain = 'bar.example.com'
        self.assertRaises(addr.UnsupportedDomain,
                          addr.canonicalizeEmailDomain,
                          domain, domainmap)

    def test_permitted(self):
        """A domain in the domainmap of allowed domains should return the
        canonical domain.
        """
        domainmap = {'foo.example.com': 'example.com'}
        domain = 'foo.example.com'
        canonical = addr.canonicalizeEmailDomain(domain, domainmap)
        self.assertEquals(canonical, 'example.com')


class ExtractEmailAddressTests(unittest.TestCase):
    """Unittests for :func:`bridgedb.parse.addr.extractEmailAddress`."""

    def test_23(self):
        """The email address int(23) should raise a BadEmail error."""
        self.assertRaises(addr.BadEmail,
                          addr.extractEmailAddress,
                          int(23))

    def test_lessThanChars(self):
        """The email address 'Alice <alice@riseup.net>' should return
        ('alice', 'riseup.net').
        """
        local, domain = addr.extractEmailAddress('Alice <alice@riseup.net>')
        self.assertEqual(local, 'alice')
        self.assertEqual(domain, 'riseup.net')

    def test_extraLessThanChars(self):
        """The email address 'Mallory <mal<lory@riseup.net>' should return
        ('lory', 'riseup.net')
        """
        local, domain = addr.extractEmailAddress('Mallory <mal<lory@riseup.net>')
        self.assertEqual(local, 'lory')
        self.assertEqual(domain, 'riseup.net')

    def test_extraLessAndGreaterThanChars(self):
        """The email address 'Mallory <mal><>>lory@riseup.net>' should raise a
        BadEmail error.
        """
        self.assertRaises(addr.BadEmail,
                          addr.extractEmailAddress,
                          'Mallory <mal><>>lory@riseup.net>')

    def test_extraAppendedEmailAddress(self):
        """The email address 'Mallory <mallory@riseup.net><mallory@gmail.com>'
        should use the last address.
        """
        local, domain = addr.extractEmailAddress(
            'Mallory <mallory@riseup.net><mallory@gmail.com>')
        self.assertEqual(local, 'mallory')
        self.assertEqual(domain, 'gmail.com')


class NormalizeEmailTests(unittest.TestCase):
    """Unittests for :func:`bridgedb.parse.addr.normalizeEmail`."""

    def test_permitted(self):
        """A valid email address from a permitted domain should return
        unchanged.
        """
        domainrules = {}
        domainmap = {'foo.example.com': 'example.com'}
        emailaddr = 'alice@foo.example.com'
        normalized = addr.normalizeEmail(emailaddr, domainmap, domainrules)
        self.assertEqual(emailaddr, normalized)

    def test_notPermitted(self):
        """A valid email address from a non-permitted domain should raise an
        UnsupportedDomain error.
        """
        domainrules = {}
        domainmap = {'bar.example.com': 'example.com'}
        emailaddr = 'Alice <alice@foo.example.com>'
        self.assertRaises(addr.UnsupportedDomain,
                          addr.normalizeEmail,
                          emailaddr, domainmap, domainrules)

    def test_ignoreDots(self):
        """A valid email address with a '.' should remove the '.' if
        'ignore_dots' is in domainrules.
        """
        domainrules = {'example.com': 'ignore_dots'}
        domainmap = {'foo.example.com': 'example.com'}
        emailaddr = 'alice.bridges@foo.example.com'
        normalized = addr.normalizeEmail(emailaddr, domainmap, domainrules)
        self.assertEqual('alicebridges@foo.example.com', normalized)

    def test_ignorePlus(self):
        """A valid email address with a '+' and some extra stuff, from a
        permitted domain, should remove the '+' stuff if 'ignore_plus' is
        enabled.
        """
        domainrules = {}
        domainmap = {'foo.example.com': 'example.com'}
        emailaddr = 'alice+bridges@foo.example.com'
        normalized = addr.normalizeEmail(emailaddr, domainmap, domainrules)
        self.assertEqual('alice@foo.example.com', normalized)

    def test_dontIgnorePlus(self):
        """A valid email address with a '+' and some extra stuff, from a
        permitted domain, should return unchanged if 'ignore_plus' is disabled.
        """
        domainrules = {}
        domainmap = {'foo.example.com': 'example.com'}
        emailaddr = 'alice+bridges@foo.example.com'
        normalized = addr.normalizeEmail(emailaddr, domainmap, domainrules,
                                         ignorePlus=False)
        self.assertEqual(emailaddr, normalized)


class ParseAddrIsIPAddressTests(unittest.TestCase):
    """Unittests for :func:`bridgedb.parse.addr.isIPAddress`.

    .. note:: All of the ``test_isIPAddress_IP*`` methods in this class should
       get ``False`` as the **result** returned from :func:`addr.isIPAddress`,
       because all the ``IP*`` constants defined above are invalid addresses
       according to :func:`addr.isValidIP`.
    """

    def test_isIPAddress_randomIP4(self):
        """Test :func:`addr.isIPAddress` with a random IPv4 address.

        This test asserts that the returned IP address is not None (because
        the IP being tested is random, it *could* randomly be an invalid IP
        address and thus :func:`~bridgdb.addr.isIPAddress` would return
        ``False``).
        """
        randomAddress = ipaddr.IPv4Address(random.getrandbits(32))
        result = addr.isIPAddress(randomAddress)
        log.msg("Got addr.isIPAddress() result for random IPv4 address %r: %s"
                % (randomAddress, result))
        self.assertTrue(result is not None)

    def test_isIPAddress_randomIP6(self):
        """Test :func:`addr.isIPAddress` with a random IPv6 address.

        This test asserts that the returned IP address is not None (because
        the IP being tested is random, it *could* randomly be an invalid IP
        address and thus :func:`~bridgdb.addr.isIPAddress` would return
        ``False``).
        """
        randomAddress = ipaddr.IPv6Address(random.getrandbits(128))
        result = addr.isIPAddress(randomAddress)
        log.msg("Got addr.isIPAddress() result for random IPv6 address %r: %s"
                % (randomAddress, result))
        self.assertTrue(result is not None)

    def runTestForAddr(self, testAddress):
        """Test :func:`addr.isIPAddress` with the specified ``testAddress``.

        :param str testAddress: A string which specifies either an IPv4 or
                                IPv6 address to test.
        """
        result = addr.isIPAddress(testAddress)
        log.msg("addr.isIPAddress(%r) => %s" % (testAddress, result))
        self.assertTrue(result is not None,
                        "Got a None for testAddress: %r" % testAddress)
        self.assertFalse(isinstance(result, basestring),
                        "Expected %r result from isIPAddress(%r): %r %r"
                        % (bool, testAddress, result, type(result)))

    def test_isIPAddress_IP4LinkLocal(self):
        """Test :func:`addr.isIPAddress` with a link local IPv4 address."""
        self.runTestForAddr(IP4LinkLocal)

    def test_isIPAddress_IP6LinkLocal(self):
        """Test :func:`addr.isIPAddress` with a link local IPv6 address."""
        self.runTestForAddr(IP6LinkLocal)

    def test_isIPAddress_IP4Loopback(self):
        """Test :func:`addr.isIPAddress` with the loopback IPv4 address."""
        self.runTestForAddr(IP4Loopback)

    def test_isIPAddress_IP4Localhost(self):
        """Test :func:`addr.isIPAddress` with a localhost IPv4 address."""
        self.runTestForAddr(IP4Localhost)

    def test_isIPAddress_IP6LinkLocal(self):
        """Test :func:`addr.isIPAddress` with a localhost IPv6 address."""
        self.runTestForAddr(IP6Localhost)

    def test_isIPAddress_IP4LimitedBroadcast(self):
        """Test :func:`addr.isIPAddress` with a limited broadcast IPv4
        address.
        """
        self.runTestForAddr(IP4LimitedBroadcast)

    def test_isIPAddress_IP4Multicast_224(self):
        """Test :func:`addr.isIPAddress` with a multicast IPv4 address."""
        self.runTestForAddr(IP4Multicast_224)

    def test_isIPAddress_IP4Multicast_239(self):
        """Test :func:`addr.isIPAddress` with a multicast IPv4 address."""
        self.runTestForAddr(IP4Multicast_239)

    def test_isIPAddress_IP4Unspecified(self):
        """Test :func:`addr.isIPAddress` with an unspecified IPv4 address."""
        self.runTestForAddr(IP4Unspecified)

    def test_isIPAddress_IP6Unspecified(self):
        """Test :func:`addr.isIPAddress` with an unspecified IPv6 address."""
        self.runTestForAddr(IP6Unspecified)

    def test_isIPAddress_IP4DefaultRoute(self):
        """Test :func:`addr.isIPAddress` with a default route IPv4 address."""
        self.runTestForAddr(IP4DefaultRoute)

    def test_isIPAddress_IP6DefaultRoute(self):
        """Test :func:`addr.isIPAddress` with a default route IPv6 address."""
        self.runTestForAddr(IP6DefaultRoute)

    def test_isIPAddress_IP4ReservedRFC1918_10(self):
        """Test :func:`addr.isIPAddress` with a reserved IPv4 address."""
        self.runTestForAddr(IP4ReservedRFC1918_10)

    def test_isIPAddress_IP4ReservedRFC1918_172_16(self):
        """Test :func:`addr.isIPAddress` with a reserved IPv4 address."""
        self.runTestForAddr(IP4ReservedRFC1918_172_16)

    def test_isIPAddress_IP4ReservedRFC1918_192_168(self):
        """Test :func:`addr.isIPAddress` with a reserved IPv4 address."""
        self.runTestForAddr(IP4ReservedRFC1918_192_168)

    def test_isIPAddress_IP4ReservedRFC1700(self):
        """Test :func:`addr.isIPAddress` with a :rfc:`1700` reserved IPv4
        address.
        """
        self.runTestForAddr(IP4ReservedRFC1700)

    def test_isIPAddress_IP6UniqueLocal(self):
        """Test :func:`addr.isIPAddress` with an unique local IPv6 address."""
        self.runTestForAddr(IP6UniqueLocal)

    def test_isIPAddress_IP6SiteLocal(self):
        """Test :func:`addr.isIPAddress` with a site local IPv6 address."""
        self.runTestForAddr(IP6SiteLocal)

    def test_isIPAddress_withNonIP(self):
        """Test :func:`addr.isIPAddress` with non-IP input."""
        self.runTestForAddr('not an ip address')

    def test_filehandle(self):
        """Test :func:`addr.isIPAddress` with a file handle for input.

        Try to raise a non- :exc:`~exceptions.ValueError` exception in
        :func:`addr.isIPAddress`.
        """
        fh = open('{0}-filehandle'.format(self.__class__.__name__), 'wb')
        self.runTestForAddr(fh)

    def test_returnUncompressedIP(self):
        """Test returning a :class:`ipaddr.IPAddress`."""
        testAddress = '86.59.30.40'
        result = addr.isIPAddress(testAddress, compressed=False)
        log.msg("addr.isIPAddress(%r, compressed=False) => %r"
                % (testAddress, result))
        self.assertTrue(
            isinstance(result, ipaddr.IPv4Address),
            "Expected %r result from isIPAddress(%r, compressed=False): %r %r"
            % (ipaddr.IPv4Address, testAddress, result, type(result)))

    def test_unicode(self):
        """Test with unicode input."""
        self.runTestForAddr("↙↓↘←↔→↖↑↗↙↓↘←↔→↖↑↗")


class ParseAddrIsIPv4Tests(unittest.TestCase):
    """Unittests for :func:`bridgedb.parse.addr.isIPv4`."""

    def runTestForIPv4(self, testAddress):
        """Test :func:`addr.isIPv4` with the specified IPv4 **testAddress**.

        This test asserts that the returned value is ``True``.

        :param str testAddress: A string which specifies the IPv4 address to
           test, which should cause :func:`addr.isIPv4` to return ``True``.
        """
        result = addr.isIPv4(testAddress)
        log.msg("addr.isIPv4(%r) => %s" % (testAddress, result))
        self.assertTrue(isinstance(result, bool),
                        "addr.isIPv4() should be boolean: %r" % type(result))
        self.assertTrue(result,
                        "addr.isIPv4(%r) should be True!" % testAddress)

    def runTestForIPv6(self, testAddress):
        """Test :func:`addr.isIPv4` with the specified IPv6 **testAddress**.

        This test asserts that the returned value is ``False``.

        :param str testAddress: A string which specifies the IPv6 address to
            test, which should cause :func:`addr.isIPv4` to return ``False``.
        """
        result = addr.isIPv4(testAddress)
        log.msg("addr.isIPv4(%r) => %s" % (testAddress, result))
        self.assertTrue(isinstance(result, bool),
                        "addr.isIPv4() should be boolean: %r" % type(result))
        self.assertFalse(result,
                         "addr.isIPv4(%r) should be False!" % testAddress)

    def test_isIPv4_randomIP4(self):
        """Test :func:`addr.isIPv4` with a random IPv4 address.

        This test asserts that the returned value is a :obj:`bool`. Because
        the IP being tested is random, it *could* randomly be an invalid IP
        address and thus :func:`~bridgdb.addr.isIPv4` would return ``False``).
        """
        randomAddr = ipaddr.IPv4Address(random.getrandbits(32)).compressed
        log.msg("Testing randomly generated IPv4 address: %s" % randomAddr)
        result = addr.isIPv4(randomAddr)
        self.assertTrue(isinstance(result, bool),
                        "addr.isIPv4() should be boolean: %r" % type(result))

    def test_isIPv4_randomIP6(self):
        """Test :func:`addr.isIPv4` with a random IPv6 address."""
        randomAddr = ipaddr.IPv6Address(random.getrandbits(128)).compressed
        log.msg("Testing randomly generated IPv6 address: %s" % randomAddr)
        self.runTestForIPv6(randomAddr)

    def test_isIPv4_IP4LinkLocal(self):
        """Test :func:`addr.isIPv4` with a link local IPv4 address."""
        self.runTestForIPv4(IP4LinkLocal)

    def test_isIPv4_IP6LinkLocal(self):
        """Test :func:`addr.isIPv4` with a link local IPv6 address."""
        self.runTestForIPv6(IP6LinkLocal)

    def test_isIPv4_IP4Loopback(self):
        """Test :func:`addr.isIPv4` with the loopback IPv4 address."""
        self.runTestForIPv4(IP4Loopback)

    def test_isIPv4_IP4Localhost(self):
        """Test :func:`addr.isIPv4` with a localhost IPv4 address."""
        self.runTestForIPv4(IP4Localhost)

    def test_isIPv4_IP6Localhost(self):
        """Test :func:`addr.isIPv4` with a localhost IPv6 address."""
        self.runTestForIPv6(IP6Localhost)

    def test_isIPv4_IP4LimitedBroadcast(self):
        """Test :func:`addr.isIPv4` with a multicast IPv4 address."""
        self.runTestForIPv4(IP4LimitedBroadcast)

    def test_isIPv4_IP4Multicast_224(self):
        """Test :func:`addr.isIPv4` with a multicast IPv4 address."""
        self.runTestForIPv4(IP4Multicast_224)

    def test_isIPv4_IP4Multicast_239(self):
        """Test :func:`addr.isIPv4` with a multicast IPv4 address."""
        self.runTestForIPv4(IP4Multicast_239)

    def test_isIPv4_IP4Unspecified(self):
        """Test :func:`addr.isIPv4` with an unspecified IPv4 address."""
        self.runTestForIPv4(IP4Unspecified)

    def test_isIPv4_IP6Unspecified(self):
        """Test :func:`addr.isIPv4` with an unspecified IPv6 address."""
        self.runTestForIPv6(IP6Unspecified)

    def test_isIPv4_IP4DefaultRoute(self):
        """Test :func:`addr.isIPv4` with a default route IPv4 address."""
        self.runTestForIPv4(IP4DefaultRoute)

    def test_isIPv4_IP6DefaultRoute(self):
        """Test :func:`addr.isIPv4` with a default route IPv6 address."""
        self.runTestForIPv6(IP6DefaultRoute)

    def test_isIPv4_IP4ReservedRFC1918_10(self):
        """Test :func:`addr.isIPv4` with a reserved IPv4 address."""
        self.runTestForIPv4(IP4ReservedRFC1918_10)

    def test_isIPv4_IP4ReservedRFC1918_172_16(self):
        """Test :func:`addr.isIPv4` with a reserved IPv4 address."""
        self.runTestForIPv4(IP4ReservedRFC1918_172_16)

    def test_isIPv4_IP4ReservedRFC1918_192_168(self):
        """Test :func:`addr.isIPv4` with a reserved IPv4 address."""
        self.runTestForIPv4(IP4ReservedRFC1918_192_168)

    def test_isIPv4_IP4ReservedRFC1700(self):
        """Test :func:`addr.isIPv4` with a :rfc:`1700` reserved IPv4
        address.
        """
        self.runTestForIPv4(IP4ReservedRFC1700)

    def test_isIPv4_IP6UniqueLocal(self):
        """Test :func:`addr.isIPv4` with an unique local IPv6 address."""
        self.runTestForIPv6(IP6UniqueLocal)

    def test_isIPv4_IP6SiteLocal(self):
        """Test :func:`addr.isIPv4` with a site local IPv6 address."""
        self.runTestForIPv6(IP6SiteLocal)

    def test_isIPv4_withValidIPv4(self):
        """Test :func:`addr.isIPv4` with a valid IPv4 address."""
        self.runTestForIPv4('38.229.72.2')

    def test_isIPv4_withValidIPv4_2(self):
        """Test :func:`addr.isIPv4` with a valid IPv4 address."""
        self.runTestForIPv4('15.15.15.15')

    def test_isIPv4_withValidIPv4_3(self):
        """Test :func:`addr.isIPv4` with a valid IPv4 address."""
        self.runTestForIPv4('93.95.227.222')

    def test_isIPv4_withValidIPv6(self):
        """Test :func:`addr.isIPv4` with a valid IPv6 address."""
        self.runTestForIPv6("2a00:1450:4001:808::1010")

    def test_isIPv4_withNonIP(self):
        """Test :func:`addr.isIPv4` with non-IP input."""
        self.runTestForIPv6('not an ip address')


class ParseAddrIsIPv6Tests(unittest.TestCase):
    """Unittests for :func:`bridgedb.parse.addr.isIPv6`.

    .. note:: All of the ``test_isIPv6_IP*`` methods in this class should get
       ``False`` as their **result** value returned from :func:`addr.isIPv6`,
       because all of the ``IP*`` constants defined above are invalid
       according to :func:`addr.isValidIP`.
    """

    def runTestForIPv4(self, testAddress):
        """Test :func:`addr.isIPv6` with the specified IPv4 **testAddress**.

        This test asserts that the returned value is ``False``.

        :param str testAddress: A string which specifies the IPv4 address to
           test, which should cause :func:`addr.isIPv6` to return ``False``.
        """
        result = addr.isIPv6(testAddress)
        log.msg("addr.isIPv6(%r) => %s" % (testAddress, result))
        self.assertTrue(isinstance(result, bool),
                        "addr.isIPv6() should be boolean: %r" % type(result))
        self.assertFalse(result,
                        "addr.isIPv6(%r) should be False!" % testAddress)

    def runTestForIPv6(self, testAddress):
        """Test :func:`addr.isIPv6` with the specified IPv6 **testAddress**.

        This test asserts that the returned value is ``True``.

        Random addresses should *not* be tested with this function, because
        :func:`~addr.isIPv6` uses :func:`~addr.isValidIP` internally, and will
        return False if the IP is invalid.

        :param str testAddress: A string which specifies the IPv6 address to
            test, which should cause :func:`addr.isIPv6` to return ``True``.
        """
        result = addr.isIPv6(testAddress)
        log.msg("addr.isIPv6(%r) => %s" % (testAddress, result))
        self.assertTrue(isinstance(result, bool),
                        "addr.isIPv6() should be boolean: %r" % type(result))
        self.assertTrue(result,
                        "addr.isIPv6(%r) should be True!" % testAddress)

    def test_isIPv6_randomIP4(self):
        """Test :func:`addr.isIPv6` with a random IPv4 address."""
        randomAddr = ipaddr.IPv4Address(random.getrandbits(32)).compressed
        log.msg("Testing randomly generated IPv4 address: %s" % randomAddr)
        self.runTestForIPv4(randomAddr)

    def test_isIPv6_randomIP6(self):
        """Test :func:`addr.isIPv6` with a random IPv6 address.

        This test asserts that the returned IP address is a :obj:`bool`
        (because the IP being tested is random, it *could* randomly be an
        invalid IP address and thus :func:`~bridgdb.addr.isIPv6` would return
        ``False``).
        """
        randomAddr = ipaddr.IPv6Address(random.getrandbits(128)).compressed
        log.msg("Testing randomly generated IPv6 address: %s" % randomAddr)
        result = addr.isIPv6(randomAddr)
        self.assertTrue(isinstance(result, bool),
                        "addr.isIPv6() should be boolean: %r" % type(result))

    def test_isIPv6_IP4LinkLocal(self):
        """Test :func:`addr.isIPv6` with a link local IPv4 address.

        :meth:`runTestForIPv4` is used because this address is invalid
        according to :func:`addr.isValidIP`; therefore, the result from
        :func:`addr.isIPv6` should be ``False``.
        """
        self.runTestForIPv4(IP4LinkLocal)

    def test_isIPv6_IP6LinkLocal(self):
        """Test :func:`addr.isIPv6` with a link local IPv6 address."""
        self.runTestForIPv6(IP6LinkLocal)

    def test_isIPv6_IP4Loopback(self):
        """Test :func:`addr.isIPv6` with the loopback IPv4 address."""
        self.runTestForIPv4(IP4Loopback)

    def test_isIPv6_IP4Localhost(self):
        """Test :func:`addr.isIPv6` with a localhost IPv4 address."""
        self.runTestForIPv4(IP4Localhost)

    def test_isIPv6_IP6Localhost(self):
        """Test :func:`addr.isIPv6` with a localhost IPv6 address."""
        self.runTestForIPv6(IP6Localhost)

    def test_isIPv6_IP4LimitedBroadcast(self):
        """Test :func:`addr.isIPv6` with a multicast IPv4 address."""
        self.runTestForIPv4(IP4LimitedBroadcast)

    def test_isIPv6_IP4Multicast_224(self):
        """Test :func:`addr.isIPv6` with a multicast IPv4 address."""
        self.runTestForIPv4(IP4Multicast_224)

    def test_isIPv6_IP4Multicast_239(self):
        """Test :func:`addr.isIPv6` with a multicast IPv4 address."""
        self.runTestForIPv4(IP4Multicast_239)

    def test_isIPv6_IP4Unspecified(self):
        """Test :func:`addr.isIPv6` with an unspecified IPv4 address."""
        self.runTestForIPv4(IP4Unspecified)

    def test_isIPv6_IP6Unspecified(self):
        """Test :func:`addr.isIPv6` with an unspecified IPv6 address."""
        self.runTestForIPv6(IP6Unspecified)

    def test_isIPv6_IP4DefaultRoute(self):
        """Test :func:`addr.isIPv6` with a default route IPv4 address."""
        self.runTestForIPv4(IP4DefaultRoute)

    def test_isIPv6_IP6DefaultRoute(self):
        """Test :func:`addr.isIPv6` with a default route IPv6 address."""
        self.runTestForIPv6(IP6DefaultRoute)

    def test_isIPv6_IP4ReservedRFC1918_10(self):
        """Test :func:`addr.isIPv6` with a reserved IPv4 address."""
        self.runTestForIPv4(IP4ReservedRFC1918_10)

    def test_isIPv6_IP4ReservedRFC1918_172_16(self):
        """Test :func:`addr.isIPv6` with a reserved IPv4 address."""
        self.runTestForIPv4(IP4ReservedRFC1918_172_16)

    def test_isIPv6_IP4ReservedRFC1918_192_168(self):
        """Test :func:`addr.isIPv6` with a reserved IPv4 address."""
        self.runTestForIPv4(IP4ReservedRFC1918_192_168)

    def test_isIPv6_IP4ReservedRFC1700(self):
        """Test :func:`addr.isIPv6` with a :rfc:`1700` reserved IPv4
        address.
        """
        self.runTestForIPv4(IP4ReservedRFC1700)

    def test_isIPv6_IP6UniqueLocal(self):
        """Test :func:`addr.isIPv6` with an unique local IPv6 address."""
        self.runTestForIPv6(IP6UniqueLocal)

    def test_isIPv6_IP6SiteLocal(self):
        """Test :func:`addr.isIPv6` with a site local IPv6 address."""
        self.runTestForIPv6(IP6SiteLocal)

    def test_isIPv6_withValidIPv4(self):
        """Test :func:`addr.isIPv6` with a valid IPv4 address."""
        self.runTestForIPv4('38.229.72.2')

    def test_isIPv6_withValidIPv4_2(self):
        """Test :func:`addr.isIPv6` with a valid IPv4 address."""
        self.runTestForIPv4('15.15.15.15')

    def test_isIPv6_withValidIPv4_3(self):
        """Test :func:`addr.isIPv6` with a valid IPv4 address."""
        self.runTestForIPv4('93.95.227.222')

    def test_isIPv6_withValidIPv6(self):
        """Test :func:`addr.isIPv6` with a valid IPv6 address."""
        self.runTestForIPv6("2a00:1450:4001:808::1010")

    def test_isIPv6_withNonIP(self):
        """Test :func:`addr.isIPv6` with non-IP input."""
        self.runTestForIPv4('not an ip address')


class PortListTest(unittest.TestCase):
    """Unittests for :class:`bridgedb.parse.addr.PortList`."""

    def getRandomPort(self):
        """Get a port in the range [1, 65535] inclusive.

        :rtype: int
        :returns: A random port number.
        """
        return random.randint(1, 65535)

    def test_tooFewPorts(self):
        """Create a :class:`addr.PortList` with no ports at all."""
        portList = addr.PortList()
        self.assertEqual(len(portList), 0)

    def test_tooManyPorts(self):
        """Create a :class:`addr.PortList` with more than the maximum
        allowed ports, as given in ``PortList.PORTSPEC_LEN``.

        We don't currently do anything to deal with a PortList having too many
        ports.
        """
        tooMany = addr.PortList.PORTSPEC_LEN + 1
        ports = [self.getRandomPort() for x in xrange(tooMany)]
        log.msg("Testing addr.PortList(%s))"
                % ', '.join([type('')(port) for port in ports]).strip(', '))
        portList = addr.PortList(*ports)
        self.assertEqual(len(portList), tooMany)

    def test_invalidPortNumber(self):
        """Test creating a :class:`addr.PortList` with an invalid port.

        Should raise an InvalidPort error.
        """
        self.assertRaises(addr.InvalidPort, addr.PortList, 66666, 6666)

    def test_contains(self):
        """Test creating a :class:`addr.PortList` with valid ports.

        Then check that ``__contains__`` works properly.
        """
        ports = (443, 9001, 9030)
        portList = addr.PortList(*ports)
        self.assertIn(443, portList)

    def test_iter(self):
        """Test creating a :class:`addr.PortList` with valid ports.

        Then check that ``__iter__`` works properly.
        """
        ports = (443, 9001, 9030)
        portList = addr.PortList(*ports)
        iterator = iter(portList)
        for x in xrange(len(ports)):
            self.assertIn(iterator.next(), portList)

    def test_str(self):
        """Test creating a :class:`addr.PortList` with valid ports.

        Then check that ``__str__`` works properly.
        """
        ports = (443, 9001, 9030)
        portList = addr.PortList(*ports)
        self.assertTrue(isinstance(str(portList), basestring))
        for port in ports:
            self.assertIn(str(port), str(portList))

    def test_getitem_shouldContain(self):
        """Test ``__getitem__`` with a port number in the PortList."""
        ports = (443, 9001, 9030)
        portList = addr.PortList(*ports)
        self.assertEqual(portList.__getitem__(0), 9001)

    def test_getitem_shouldNotContain(self):
        """Test ``__getitem__`` with a port number not in the PortList."""
        ports = (443, 9001, 9030)
        portList = addr.PortList(*ports)
        self.assertRaises(IndexError, portList.__getitem__, 555)

    def test_getitem_string(self):
        """Test ``__getitem__`` with a string."""
        ports = (443, 9001, 9030)
        portList = addr.PortList(*ports)
        self.assertRaises(TypeError, portList.__getitem__, '443')

    def test_getitem_long(self):
        """Test ``__getitem__`` with a string."""
        ports = (443, 9001, 9030)
        portList = addr.PortList(*ports)
        self.assertEqual(portList.__getitem__(long(0)), 9001)

    def test_mixedArgs(self):
        """Create a :class:`addr.PortList` with mixed type parameters."""
        firstList = addr.PortList('1111,2222,3333')
        portList = addr.PortList(443, "9001,9030, 9050", firstList)
        self.assertTrue(portList)

    def test_invalidStringArgs(self):
        """Create a :class:`addr.PortList` with mixed type parameters."""
        self.assertRaises(addr.InvalidPort,
                          addr.PortList, '1111, 666666, 3333')
