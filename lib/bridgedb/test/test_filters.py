# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013-2015 Isis Lovecruft
#             (c) 2007-2015, The Tor Project, Inc.
# :license: see included LICENSE for information

"""Tests for :mod:`bridgedb.filters`."""

from __future__ import print_function

import ipaddr

from twisted.trial import unittest

from bridgedb import filters
from bridgedb.bridges import Bridge
from bridgedb.bridges import PluggableTransport


class FiltersTests(unittest.TestCase):
    """Tests for :mod:`bridgedb.filters`."""

    def test_byIPv4_address(self):
        """A bridge with an IPv4 address for its main orPort address should
        cause filters.byIPv4() to return True.
        """
        bridge = Bridge()
        bridge.address = '1.1.1.1'
        bridge.orPort = 1111
        self.assertTrue(filters.byIPv4(bridge))

    def test_byIPv4_orAddress(self):
        """A bridge with an IPv4 address in its orAddresses address should
        cause filters.byIPv4() to return True.
        """
        bridge = Bridge()
        bridge.address = '2006:2222::2222'
        bridge.orPort = 1111
        bridge.orAddresses = [(ipaddr.IPv4Address('2.2.2.2'), 2222, 4)]
        self.assertTrue(filters.byIPv4(bridge))

    def test_byIPv4_none(self):
        """A bridge with no IPv4 addresses should cause filters.byIPv4() to
        return False.
        """
        bridge = Bridge()
        bridge.address = ipaddr.IPv6Address('2006:2222::2222')
        bridge.orPort = 1111
        bridge.orAddresses = [(ipaddr.IPv6Address('2006:3333::3333'), 3333, 6)]
        self.assertFalse(filters.byIPv4(bridge))

    def test_byIPv6_address(self):
        """A bridge with an IPv6 address for its main orPort address should
        cause filters.byIPv6() to return True.
        """
        bridge = Bridge()
        bridge.address = '2006:2222::2222'
        bridge.orPort = 1111
        self.assertTrue(filters.byIPv6(bridge))

    def test_byIPv6_orAddress(self):
        """A bridge with an IPv6 address in its orAddresses address should
        cause filters.byIPv6() to return True.
        """
        bridge = Bridge()
        bridge.address = '1.1.1.1'
        bridge.orPort = 1111
        bridge.orAddresses = [(ipaddr.IPv6Address('2006:3333::3333'), 3333, 6)]
        self.assertTrue(filters.byIPv6(bridge))

    def test_byIPv6_none(self):
        """A bridge with no IPv6 addresses should cause filters.byIPv6() to
        return False.
        """
        bridge = Bridge()
        bridge.address = '1.1.1.1'
        bridge.orPort = 1111
        self.assertFalse(filters.byIPv6(bridge))

    def test_byTransport_with_transport_ipv4(self):
        """A bridge with an IPv4 voltron transport should cause
        byTransport('voltron') to return True.
        """
        bridge = Bridge()
        pt = PluggableTransport('a'*40, 'voltron', '1.1.1.1', 1111, {})
        bridge.transports.append(pt)
        filtre = filters.byTransport('voltron')
        self.assertTrue(filtre(bridge))

    def test_byTransport_with_transport_ipv6(self):
        """A bridge with an IPv6 voltron transport should cause
        byTransport('voltron') to return True.
        """
        bridge = Bridge()
        pt = PluggableTransport('a'*40, 'voltron', '2006:2222::2222', 1111, {})
        bridge.transports.append(pt)
        filtre = filters.byTransport('voltron', ipVersion=6)
        self.assertTrue(filtre(bridge))

    def test_byTransport_no_transports(self):
        """A bridge without any transports should cause
        byTransport('voltron') to return False.
        """
        bridge = Bridge()
        filtre = filters.byTransport('voltron')
        self.assertFalse(filtre(bridge))

    def test_byTransport_wrong_transport(self):
        """A bridge with only an obfs3 transport should cause
        byTransport('voltron') to return False.
        """
        bridge = Bridge()
        pt = PluggableTransport('a'*40, 'obfs3', '2.2.2.2', 1111, {})
        bridge.transports.append(pt)
        filtre = filters.byTransport('voltron')
        self.assertFalse(filtre(bridge))

    def test_byNotBlockedIn_no_countryCode_with_transport_ipv4(self):
        """A bridge with an IPv4 voltron transport should cause
        byNotBlockedIn('voltron') to return True (because it calls
        filters.byTransport).
        """
        bridge = Bridge()
        pt = PluggableTransport('a'*40, 'voltron', '1.1.1.1', 1111, {})
        bridge.transports.append(pt)
        filtre = filters.byNotBlockedIn(None, methodname='voltron')
        self.assertTrue(filtre(bridge))

    def test_byNotBlockedIn_no_countryCode_with_transport_ipv6(self):
        """A bridge with an IPv6 voltron transport should cause
        byNotBlockedIn('voltron') to return True (because it calls
        filters.byTransport).
        """
        bridge = Bridge()
        pt = PluggableTransport('a'*40, 'voltron', '2006:2222::2222', 1111, {})
        bridge.transports.append(pt)
        filtre = filters.byNotBlockedIn(None, methodname='voltron', ipVersion=6)
        self.assertTrue(filtre(bridge))

    def test_byNotBlockedIn_with_transport_ipv4(self):
        """A bridge with an IPv4 voltron transport should cause
        byNotBlockedIn('voltron') to return True.
        """
        bridge = Bridge()
        pt = PluggableTransport('a'*40, 'voltron', '1.1.1.1', 1111, {})
        bridge.transports.append(pt)
        filtre = filters.byNotBlockedIn('CN', methodname='voltron')
        self.assertTrue(filtre(bridge))

    def test_byNotBlockedIn_with_transport_ipv4_blocked(self):
        """A bridge with an IPv4 voltron transport which is blocked should
        cause byNotBlockedIn('voltron') to return False.
        """
        bridge = Bridge()
        pt = PluggableTransport('a'*40, 'voltron', '1.1.1.1', 1111, {})
        bridge.transports.append(pt)
        bridge.setBlockedIn('CN')
        filtre = filters.byNotBlockedIn('CN', methodname='voltron')
        self.assertFalse(filtre(bridge))

    def test_byNotBlockedIn_with_transport_ipv6(self):
        """A bridge with an IPv6 voltron transport should cause
        byNotBlockedIn('voltron') to return True.
        """
        bridge = Bridge()
        pt = PluggableTransport('a'*40, 'voltron', '2006:2222::2222', 1111, {})
        bridge.transports.append(pt)
        filtre = filters.byNotBlockedIn('cn', 'voltron', ipVersion=6)
        self.assertTrue(filtre(bridge))

    def test_byNotBlockedIn_with_transport_ipv6_blocked(self):
        """A bridge with an IPv6 voltron transport which is blocked should
        cause byNotBlockedIn('voltron') to return False.
        """
        bridge = Bridge()
        pt = PluggableTransport('a'*40, 'voltron', '2006:2222::2222', 1111, {})
        bridge.transports.append(pt)
        bridge.setBlockedIn('CN')
        filtre = filters.byNotBlockedIn('cn', 'voltron', ipVersion=6)
        self.assertFalse(filtre(bridge))

    def test_byNotBlockedIn_no_countryCode_no_transports(self):
        """A bridge without any transports should cause
        byNotBlockedIn('voltron') to return False (because it calls
        filters.byTransport()).
        """
        bridge = Bridge()
        filtre = filters.byNotBlockedIn(None, methodname='voltron')
        self.assertFalse(filtre(bridge))

    def test_byNotBlockedIn_no_transports(self):
        """A bridge without any transports should cause
        byNotBlockedIn('voltron') to return False.
        """
        bridge = Bridge()
        filtre = filters.byNotBlockedIn('cn', methodname='voltron')
        self.assertFalse(filtre(bridge))

    def test_byNotBlockedIn_no_transports_blocked(self):
        """A bridge without any transports which is also blocked should cause
        byNotBlockedIn('voltron') to return False.
        """
        bridge = Bridge()
        bridge.address = '1.1.1.1'
        bridge.orPort = 1111
        bridge.setBlockedIn('cn')
        filtre = filters.byNotBlockedIn('cn', methodname='voltron')
        self.assertFalse(filtre(bridge))

    def test_byNotBlockedIn_wrong_transport(self):
        """A bridge with only an obfs3 transport should cause
        byNotBlockedIn('voltron') to return False.
        """
        bridge = Bridge()
        pt = PluggableTransport('a'*40, 'obfs3', '2.2.2.2', 1111, {})
        bridge.transports.append(pt)
        filtre = filters.byNotBlockedIn('cn', methodname='voltron')
        self.assertFalse(filtre(bridge))
