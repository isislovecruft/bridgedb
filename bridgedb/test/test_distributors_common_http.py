# -*- coding: utf-8 -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2014-2017, Isis Lovecruft
#             (c) 2014-2017, The Tor Project, Inc.
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""Unittests for :mod:`bridgedb.distributors.common.http`."""

from __future__ import print_function

import logging
import os

from twisted.trial import unittest
from twisted.web.test import requesthelper

from bridgedb.distributors.common import http as server

from bridgedb.test.https_helpers import DummyRequest


# For additional logger output for debugging, comment out the following:
logging.disable(50)
# and then uncomment the following line:
#server.logging.getLogger().setLevel(10)


class SetFQDNTests(unittest.TestCase):
    """Tests for :func:`bridgedb.distributors.https.server.setFQDN` and
    :func:`bridgedb.distributors.https.server.setFQDN`.
    """

    def setUp(self):
        self.originalFQDN = server.SERVER_PUBLIC_FQDN

    def tearDown(self):
        server.SERVER_PUBLIC_FQDN = self.originalFQDN

    def test_setFQDN_https(self):
        """Calling ``server.setFQDN([…], https=True)`` should prepend
        ``"https://"`` to the module :data:`server.SERVER_PUBLIC_FQDN`
        variable.
        """
        server.setFQDN('example.com', https=True)
        self.assertEqual(server.SERVER_PUBLIC_FQDN, "https://example.com")

    def test_setFQDN_http(self):
        """Calling ``server.setFQDN([…], https=False)`` should not prepend
        anything at all to the module :data:`server.SERVER_PUBLIC_FQDN`
        variable.
        """
        server.setFQDN('example.com', https=False)
        self.assertEqual(server.SERVER_PUBLIC_FQDN, "example.com")


class GetClientIPTests(unittest.TestCase):
    """Tests for :func:`bridgedb.distributors.https.server.getClientIP`."""

    def createRequestWithIPs(self):
        """Set the IP address returned from ``request.getClientIP()`` to
        '3.3.3.3', and the IP address reported in the 'X-Forwarded-For' header
        to '2.2.2.2'.
        """
        request = DummyRequest([''])
        request.headers.update({'x-forwarded-for': '2.2.2.2'})
        # See :api:`twisted.test.requesthelper.DummyRequest.getClientIP`
        request.client = requesthelper.IPv4Address('TCP', '3.3.3.3', 443)
        request.method = b'GET'
        return request

    def test_getClientIP_XForwardedFor(self):
        """getClientIP() should return the IP address from the
        'X-Forwarded-For' header when ``useForwardedHeader=True``.
        """
        request = self.createRequestWithIPs()
        clientIP = server.getClientIP(request, useForwardedHeader=True)
        self.assertEqual(clientIP, '2.2.2.2')

    def test_getClientIP_XForwardedFor_bad_ip(self):
        """getClientIP() should return None if the IP address from the
        'X-Forwarded-For' header is bad/invalid and
        ``useForwardedHeader=True``.
        """
        request = self.createRequestWithIPs()
        request.headers.update({'x-forwarded-for': 'pineapple'})
        clientIP = server.getClientIP(request, useForwardedHeader=True)
        self.assertEqual(clientIP, None)

    def test_getClientIP_XForwardedFor_skip_loopback(self):
        request = self.createRequestWithIPs()
        request.headers.update({'x-forwarded-for': '3.3.3.3, 127.0.0.1'})
        clientIP = server.getClientIP(request, useForwardedHeader=True, skipLoopback=True)
        self.assertEqual(clientIP, '3.3.3.3')

    def test_getClientIP_XForwardedFor_skip_loopback_multiple(self):
        request = self.createRequestWithIPs()
        request.headers.update({'x-forwarded-for': '3.3.3.3, 127.0.0.6, 127.0.0.1'})
        clientIP = server.getClientIP(request, useForwardedHeader=True, skipLoopback=True)
        self.assertEqual(clientIP, '3.3.3.3')

    def test_getClientIP_XForwardedFor_no_skip_loopback(self):
        request = self.createRequestWithIPs()
        request.headers.update({'x-forwarded-for': '3.3.3.3, 127.0.0.1'})
        clientIP = server.getClientIP(request, useForwardedHeader=True, skipLoopback=False)
        self.assertEqual(clientIP, '127.0.0.1')

    def test_getClientIP_fromRequest(self):
        """getClientIP() should return the IP address from the request instance
        when ``useForwardedHeader=False``.
        """
        request = self.createRequestWithIPs()
        clientIP = server.getClientIP(request)
        self.assertEqual(clientIP, '3.3.3.3')
