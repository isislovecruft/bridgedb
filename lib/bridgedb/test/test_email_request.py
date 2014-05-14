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

"""Unittests for the :mod:`bridgedb.email.request` module."""

from __future__ import print_function

import ipaddr

from twisted.trial import unittest

from bridgedb.email import request


class DetermineBridgeRequestOptionsTests(unittest.TestCase):
    """Unittests for :func:`b.e.request.determineBridgeRequestOptions`."""

    def test_determineBridgeRequestOptions_get_help(self):
        """Requesting 'get help' should raise EmailRequestedHelp."""
        lines = ['',
                 'get help']
        self.assertRaises(request.EmailRequestedHelp,
                          request.determineBridgeRequestOptions, lines)
        
    def test_determineBridgeRequestOptions_get_halp(self):
        """Requesting 'get halp' should raise EmailRequestedHelp."""
        lines = ['',
                 'get halp']
        self.assertRaises(request.EmailRequestedHelp,
                          request.determineBridgeRequestOptions, lines)
        
    def test_determineBridgeRequestOptions_get_key(self):
        """Requesting 'get key' should raise EmailRequestedKey."""
        lines = ['',
                 'get key']
        self.assertRaises(request.EmailRequestedKey,
                          request.determineBridgeRequestOptions, lines)

    def test_determineBridgeRequestOptions_multiline_invalid(self):
        """Requests without a 'get' anywhere should be considered invalid."""
        lines = ['',
                 'transport obfs3',
                 'ipv6 vanilla bridges',
                 'give me your gpgs']
        reqvest = request.determineBridgeRequestOptions(lines)
        # It's invalid because it didn't include a 'get' anywhere.
        self.assertEqual(reqvest.isValid(), False)
        self.assertFalse(reqvest.wantsKey())
        # Though they did request IPv6, technically.
        self.assertIs(reqvest.addressClass, ipaddr.IPv6Address)
        # And they did request a transport, technically.
        self.assertEqual(len(reqvest.transports), 1)
        self.assertEqual(reqvest.transports[0], 'obfs3')

    def test_determineBridgeRequestOptions_multiline_valid(self):
        """Though requests with a 'get' are considered valid."""
        lines = ['',
                 'get transport obfs3',
                 'vanilla bridges',
                 'transport scramblesuit unblocked ca']
        reqvest = request.determineBridgeRequestOptions(lines)
        # It's valid because it included a 'get'.
        self.assertEqual(reqvest.isValid(), True)
        self.assertFalse(reqvest.wantsKey())
        # Though they didn't request IPv6, so it should default to IPv4.
        self.assertIs(reqvest.addressClass, ipaddr.IPv4Address)
        # And they requested two transports.
        self.assertEqual(len(reqvest.transports), 2)
        self.assertEqual(reqvest.transports[0], 'obfs3')
        self.assertEqual(reqvest.transports[1], 'scramblesuit')
        # And they wanted this stuff to not be blocked in Canada.
        self.assertEqual(len(reqvest.notBlockedIn), 1)
        self.assertEqual(reqvest.notBlockedIn[0], 'ca')

    def test_determineBridgeRequestOptions_multiline_valid_OMG_CAPSLOCK(self):
        """Though requests with a 'get' are considered valid, even if they
        appear to not know the difference between Capslock and Shift.
        """
        lines = ['',
                 'get TRANSPORT obfs3',
                 'vanilla bridges',
                 'TRANSPORT SCRAMBLESUIT UNBLOCKED CA']
        reqvest = request.determineBridgeRequestOptions(lines)
        # It's valid because it included a 'get'.
        self.assertEqual(reqvest.isValid(), True)
        self.assertFalse(reqvest.wantsKey())
        # Though they didn't request IPv6, so it should default to IPv4.
        self.assertIs(reqvest.addressClass, ipaddr.IPv4Address)
        # And they requested two transports.
        self.assertEqual(len(reqvest.transports), 2)
        self.assertEqual(reqvest.transports[0], 'obfs3')
        self.assertEqual(reqvest.transports[1], 'scramblesuit')
        # And they wanted this stuff to not be blocked in Canada.
        self.assertEqual(len(reqvest.notBlockedIn), 1)
        self.assertEqual(reqvest.notBlockedIn[0], 'ca')

    def test_determineBridgeRequestOptions_get_transport(self):
        """An invalid request for 'transport obfs3' (missing the 'get')."""
        lines = ['',
                 'transport obfs3']
        reqvest = request.determineBridgeRequestOptions(lines)
        self.assertEqual(len(reqvest.transports), 1)
        self.assertEqual(reqvest.transports[0], 'obfs3')
        self.assertEqual(reqvest.isValid(), False)
        
    def test_determineBridgeRequestOptions_get_ipv6(self):
        """An valid request for 'get ipv6'."""
        lines = ['',
                 'get ipv6']
        reqvest = request.determineBridgeRequestOptions(lines)
        self.assertIs(reqvest.addressClass, ipaddr.IPv6Address)
        self.assertEqual(reqvest.isValid(), True)


class EmailBridgeRequestTests(unittest.TestCase):
    """Unittests for :class:`b.e.request.EmailBridgeRequest`."""

    def setUp(self):
        """Create an EmailBridgeRequest instance to test."""
        self.request = request.EmailBridgeRequest()

    def tearDown(self):
        """Reset cached 'unblocked'/'transport' lists and addressClass between
        tests.
        """
        self.request.withIPv4()
        self.request.notBlockedIn = []
        self.request.transports = []

    def test_EmailBridgeRequest_isValid_initial(self):
        """Initial value of EmailBridgeRequest.isValid() should be False."""
        self.request.isValid(None)
        self.assertEqual(self.request.isValid(), False)

    def test_EmailBridgeRequest_isValid_True(self):
        """The value of EmailBridgeRequest.isValid() should be True, after it
        has been called with ``True`` as an argument.
        """
        self.request.isValid(True)
        self.assertEqual(self.request.isValid(), True)

    def test_EmailBridgeRequest_isValid_False(self):
        """The value of EmailBridgeRequest.isValid() should be False, after it
        has been called with ``False`` as an argument.
        """
        self.request.isValid(False)
        self.assertEqual(self.request.isValid(), False)

    def test_EmailBridgeRequest_wantsKey_initial(self):
        """Initial value of EmailBridgeRequest.wantsKey() should be False."""
        self.request.wantsKey(None)
        self.assertEqual(self.request.wantsKey(), False)

    def test_EmailBridgeRequest_wantsKey_True(self):
        """The value of EmailBridgeRequest.wantsKey() should be True, after it
        has been called with ``True`` as an argument.
        """
        self.request.wantsKey(True)
        self.assertEqual(self.request.wantsKey(), True)

    def test_EmailBridgeRequest_wantsKey_False(self):
        """The value of EmailBridgeRequest.wantsKey() should be False, after
        it has been called with ``False`` as an argument.
        """
        self.request.wantsKey(False)
        self.assertEqual(self.request.wantsKey(), False)

    def test_EmailBridgeRequest_withIPv6(self):
        """IPv6 requests should have ``addressClass = ipaddr.IPv6Address``."""
        self.assertEqual(self.request.addressClass, ipaddr.IPv4Address)
        self.request.withIPv6()
        self.assertEqual(self.request.addressClass, ipaddr.IPv6Address)

    def test_EmailBridgeRequest_withoutBlockInCountry_CN(self):
        """Country codes that aren't lowercase should be ignored."""
        self.request.withoutBlockInCountry('get unblocked CN')
        self.assertIsInstance(self.request.notBlockedIn, list)
        self.assertEqual(len(self.request.notBlockedIn), 0)

    def test_EmailBridgeRequest_withoutBlockInCountry_cn(self):
        """Lowercased country codes are okay though."""
        self.request.withoutBlockInCountry('get unblocked cn')
        self.assertIsInstance(self.request.notBlockedIn, list)
        self.assertEqual(len(self.request.notBlockedIn), 1)

    def test_EmailBridgeRequest_withoutBlockInCountry_cn_getMissing(self):
        """Lowercased country codes are still okay if the 'get' is missing."""
        self.request.withoutBlockInCountry('unblocked cn')
        self.assertIsInstance(self.request.notBlockedIn, list)
        self.assertEqual(len(self.request.notBlockedIn), 1)

    def test_EmailBridgeRequest_withoutBlockInCountry_multiline_cn_ir_li(self):
        """Requests for multiple unblocked countries should compound if they
        are on separate 'get unblocked' lines.
        """
        self.request.withoutBlockInCountry('get unblocked cn')
        self.request.withoutBlockInCountry('get unblocked ir')
        self.request.withoutBlockInCountry('get unblocked li')
        self.assertIsInstance(self.request.notBlockedIn, list)
        self.assertEqual(len(self.request.notBlockedIn), 3)

    def test_EmailBridgeRequest_withoutBlockInCountry_singleline_cn_ir_li(self):
        """Requests for multiple unblocked countries which are all on the same
        'get unblocked' line will use only the *first* country code.
        """
        self.request.withoutBlockInCountry('get unblocked cn ir li')
        self.assertIsInstance(self.request.notBlockedIn, list)
        self.assertEqual(len(self.request.notBlockedIn), 1)

    def test_EmailBridgeRequest_withPluggableTransportType_SCRAMBLESUIT(self):
        """Transports which aren't in lowercase should be ignored."""
        self.request.withPluggableTransportType('get transport SCRAMBLESUIT')
        self.assertIsInstance(self.request.transports, list)
        self.assertEqual(len(self.request.transports), 0)

    def test_EmailBridgeRequest_withPluggableTransportType_scramblesuit(self):
        """Lowercased transports are okay though."""
        self.request.withPluggableTransportType('get transport scramblesuit')
        self.assertIsInstance(self.request.transports, list)
        self.assertEqual(len(self.request.transports), 1)
        self.assertEqual(self.request.transports[0], 'scramblesuit')

    def test_EmailBridgeRequest_withPluggableTransportType_scramblesuit_getMissing(self):
        """Lowercased transports are still okay if 'get' is missing."""
        self.request.withPluggableTransportType('transport scramblesuit')
        self.assertIsInstance(self.request.transports, list)
        self.assertEqual(len(self.request.transports), 1)
        self.assertEqual(self.request.transports[0], 'scramblesuit')

    def test_EmailBridgeRequest_withPluggableTransportType_multiline_obfs3_obfs2_scramblesuit(self):
        """Requests for multiple pluggable transports should compound if they
        are on separate 'get transport' lines.
        """
        self.request.withPluggableTransportType('get transport obfs3')
        self.request.withPluggableTransportType('get transport obfs2')
        self.request.withPluggableTransportType('get transport scramblesuit')
        self.assertIsInstance(self.request.transports, list)
        self.assertEqual(len(self.request.transports), 3)
        self.assertEqual(self.request.transports[0], 'obfs3')

    def test_EmailBridgeRequest_withPluggableTransportType_singleline_obfs3_obfs2_scramblesuit(self):
        """Requests for multiple transports which are all on the same
        'get transport' line will use only the *first* transport.
        """
        self.request.withPluggableTransportType('get transport obfs3 obfs2 scramblesuit')
        self.assertIsInstance(self.request.transports, list)
        self.assertEqual(len(self.request.transports), 1)
        self.assertEqual(self.request.transports[0], 'obfs3')

    def test_EmailBridgeRequest_withPluggableTransportType_whack(self):
        """Requests for whacky transports that don't exist are also okay."""
        self.request.withPluggableTransportType('get transport whack')
        self.assertIsInstance(self.request.transports, list)
        self.assertEqual(len(self.request.transports), 1)
        self.assertEqual(self.request.transports[0], 'whack')

    def test_EmailBridgeRequest_justOnePTType_obfs3_obfs2_scramblesuit(self):
        """Requests for multiple transports when
        ``EmailBridgeRequest.justOneTransport()`` is used will use only the
        *last* transport.
        """
        self.request.withPluggableTransportType('get transport obfs3')
        self.request.withPluggableTransportType('get transport obfs2')
        self.request.withPluggableTransportType('get transport scramblesuit')
        self.assertIsInstance(self.request.transports, list)
        self.assertEqual(len(self.request.transports), 3)
        self.assertEqual(self.request.transports[0], 'obfs3')
        self.assertEqual(self.request.justOnePTType(), 'scramblesuit')
