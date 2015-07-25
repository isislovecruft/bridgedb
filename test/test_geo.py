# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2015, The Tor Project, Inc.
#             (c) 2007-2015, Isis Lovecruft
# :license: see LICENSE for licensing information

"""Unittests for the :mod:`bridgedb.geo` module."""

import ipaddr

from twisted.trial import unittest

from bridgedb import geo


class GeoTests(unittest.TestCase):
    """Unittests for the :mod:`bridgedb.geo` module."""

    def setUp(self):
        self._orig_geoip = geo.geoip
        self._orig_geoipv6 = geo.geoipv6

        self.ipv4 = ipaddr.IPAddress('38.229.72.16')
        self.ipv6 = ipaddr.IPAddress('2620:0:6b0:b:1a1a:0:26e5:4810')

        # WARNING: this is going to fail if the torproject.org A and AAAA
        # records above are reassigned to another host, or are randomly
        # geolocated to somewhere other than where they are currently
        # geolocated (in the US):
        self.expectedCC = 'US'

    def tearDown(self):
        geo.geoip = self._orig_geoip
        geo.geoipv6 = self._orig_geoipv6

    def test_geo_getCountryCode_ipv4_str(self):
        """Should return None since the IP isn't an ``ipaddr.IPAddress``."""
        self.assertIsNone(geo.getCountryCode(str(self.ipv4)))

    def test_geo_getCountryCode_ipv4_no_geoip_loopback(self):
        """Should return None since this IP isn't geolocatable (hopefully ever)."""
        ipv4 = ipaddr.IPAddress('127.0.0.1')
        self.assertIsNone(geo.getCountryCode(ipv4))

    def test_geo_getCountryCode_ipv4_class(self):
        """Should return the CC since the IP is an ``ipaddr.IPAddress``."""
        cc = geo.getCountryCode(self.ipv4)
        self.assertIsNotNone(cc)
        self.assertIsInstance(cc, basestring)
        self.assertEqual(len(cc), 2)
        self.assertEqual(cc, self.expectedCC)

    def test_geo_getCountryCode_ipv6_str(self):
        """Should return None since the IP isn't an ``ipaddr.IPAddress``."""
        self.assertIsNone(geo.getCountryCode(str(self.ipv6)))

    def test_geo_getCountryCode_ipv6_no_geoip_record(self):
        """Should return None since this IP isn't geolocatable (yet)."""
        ipv6 = ipaddr.IPAddress('20::72a:e224:44d8:a606:4115')
        self.assertIsNone(geo.getCountryCode(ipv6))

    def test_geo_getCountryCode_ipv6_no_geoip_link_local(self):
        """Should return None since this IP isn't geolocatable (hopefully ever)."""
        ipv6 = ipaddr.IPAddress('ff02::')
        self.assertIsNone(geo.getCountryCode(ipv6))

    def test_geo_getCountryCode_ipv6_no_geoip_loopback(self):
        """Should return None since this IP isn't geolocatable (hopefully ever)."""
        ipv6 = ipaddr.IPAddress('::1')
        self.assertIsNone(geo.getCountryCode(ipv6))

    def test_geo_getCountryCode_ipv6_class(self):
        """Should return the CC since the IP is an ``ipaddr.IPAddress``."""
        cc = geo.getCountryCode(self.ipv6)
        self.assertIsNotNone(cc)
        self.assertIsInstance(cc, basestring)
        self.assertEqual(len(cc), 2)
        self.assertEqual(cc, self.expectedCC)

    def test_geo_getCountryCode_no_geoip(self):
        """When missing the geo.geoip database, getCountryCode() should return
        None.
        """
        geo.geoip = None
        self.assertIsNone(geo.getCountryCode(self.ipv4))

    def test_geo_getCountryCode_no_geoipv6(self):
        """When missing the geo.geoipv6 database, getCountryCode() should
        return None.
        """
        geo.geoipv6 = None
        self.assertIsNone(geo.getCountryCode(self.ipv4))
