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
from bridgedb.crypto import getHMACFunc


class FiltersTests(unittest.TestCase):
    """Tests for :mod:`bridgedb.filters`."""

    def setUp(self):
        """Create a Bridge whose address is 1.1.1.1, orPort is 1111, and
        fingerprint is 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'.  Also,
        create an HMAC function whose key is 'plasma'.
        """
        self.bridge = Bridge()
        self.bridge.address = '1.1.1.1'
        self.bridge.orPort = 1111
        self.bridge.fingerprint = 'a' * 40

        self.hmac = getHMACFunc('plasma')

    def addIPv4VoltronPT(self):
        pt = PluggableTransport('a' * 40, 'voltron', '1.1.1.1', 1111, {})
        self.bridge.transports.append(pt)

    def addIPv6VoltronPT(self):
        pt = PluggableTransport('a' * 40, 'voltron', '2006:2222::2222', 1111, {})
        self.bridge.transports.append(pt)

    def test_bySubring_1_of_2(self):
        """A Bridge with fingerprint 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        should be assigned to sub-hashring 1-of-2 (in this case, using a
        particular HMAC key), and therefore filters.bySubring(HMAC, 1, 2)
        should return that Bridge (because it is in the sub-hashring we asked
        for).
        """
        filtre = filters.bySubring(self.hmac, 1, 2)
        self.assertTrue(filtre(self.bridge))

    def test_bySubring_2_of_2(self):
        """A Bridge with fingerprint 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        should be assigned to sub-hashring 1-of-2 (in this case, using a
        particular HMAC key), and therefore filters.bySubring(HMAC, 2, 2)
        should *not* return that Bridge (because it is in sub-hashring 1-of-2
        and we asked for Bridges which are in sub-hashring 2-of-2).
        """
        filtre = filters.bySubring(self.hmac, 2, 2)
        self.assertFalse(filtre(self.bridge))

    def test_byFilters_bySubring_byTransport_correct_subhashring_with_transport(self):
        """Filtering byTransport('voltron') and bySubring(HMAC, 1, 2) when the
        Bridge has a voltron transport and is assigned to sub-hashring 1-of-2
        should return True.
        """
        self.addIPv4VoltronPT()
        filtre = filters.byFilters([filters.bySubring(self.hmac, 1, 2),
                                    filters.byTransport('voltron')])
        self.assertTrue(filtre(self.bridge))

    def test_byFilters_bySubring_byTransport_wrong_subhashring_with_transport(self):
        """Filtering byTransport('voltron') and bySubring(HMAC, 2, 2) when the
        Bridge has a voltron transport and is assigned to sub-hashring 1-of-2
        should return False.
        """
        self.addIPv4VoltronPT()
        filtre = filters.byFilters([filters.bySubring(self.hmac, 2, 2),
                                    filters.byTransport('voltron')])
        self.assertFalse(filtre(self.bridge))

    def test_byFilters_bySubring_byTransport_correct_subhashring_no_transport(self):
        """Filtering byTransport('voltron') and bySubring(HMAC, 1, 2) when the
        Bridge has no transports and is assigned to sub-hashring 1-of-2
        should return False.
        """
        filtre = filters.byFilters([filters.bySubring(self.hmac, 1, 2),
                                    filters.byTransport('voltron')])
        self.assertFalse(filtre(self.bridge))

    def test_byFilters_bySubring_byTransport_wrong_subhashring_no_transport(self):
        """Filtering byTransport('voltron') and bySubring(HMAC, 2, 2) when the
        Bridge has no transports and is assigned to sub-hashring 1-of-2
        should return False.
        """
        filtre = filters.byFilters([filters.bySubring(self.hmac, 2, 2),
                                    filters.byTransport('voltron')])
        self.assertFalse(filtre(self.bridge))

    def test_byFilters_no_filters(self):
        self.addIPv4VoltronPT()
        filtre = filters.byFilters([])
        self.assertTrue(filtre(self.bridge))

    def test_byIPv_ipv5(self):
        """Calling byIPv(ipVersion=5) should default to filterint by IPv4."""
        filtre = filters.byIPv(5)
        self.assertTrue(filtre(self.bridge))

    def test_byIPv4_address(self):
        """A bridge with an IPv4 address for its main orPort address should
        cause filters.byIPv4() to return True.
        """
        self.assertTrue(filters.byIPv4(self.bridge))

    def test_byIPv4_orAddress(self):
        """A bridge with an IPv4 address in its orAddresses address should
        cause filters.byIPv4() to return True.
        """
        self.bridge.address = '2006:2222::2222'
        self.bridge.orAddresses = [(ipaddr.IPv4Address('2.2.2.2'), 2222, 4)]
        self.assertTrue(filters.byIPv4(self.bridge))

    def test_byIPv4_none(self):
        """A bridge with no IPv4 addresses should cause filters.byIPv4() to
        return False.
        """
        self.bridge.address = ipaddr.IPv6Address('2006:2222::2222')
        self.bridge.orAddresses = [(ipaddr.IPv6Address('2006:3333::3333'), 3333, 6)]
        self.assertFalse(filters.byIPv4(self.bridge))

    def test_byIPv6_address(self):
        """A bridge with an IPv6 address for its main orPort address should
        cause filters.byIPv6() to return True.
        """
        self.bridge.address = '2006:2222::2222'
        self.assertTrue(filters.byIPv6(self.bridge))

    def test_byIPv6_orAddress(self):
        """A bridge with an IPv6 address in its orAddresses address should
        cause filters.byIPv6() to return True.
        """
        self.bridge.orAddresses = [(ipaddr.IPv6Address('2006:3333::3333'), 3333, 6)]
        self.assertTrue(filters.byIPv6(self.bridge))

    def test_byIPv6_none(self):
        """A bridge with no IPv6 addresses should cause filters.byIPv6() to
        return False.
        """
        self.assertFalse(filters.byIPv6(self.bridge))

    def test_byTransport_with_transport_ipv4(self):
        """A bridge with an IPv4 voltron transport should cause
        byTransport('voltron') to return True.
        """
        self.addIPv4VoltronPT()
        filtre = filters.byTransport('voltron')
        self.assertTrue(filtre(self.bridge))

    def test_byTransport_with_transport_ipv6(self):
        """A bridge with an IPv6 voltron transport should cause
        byTransport('voltron', ipVersion=6) to return True.
        """
        self.addIPv6VoltronPT()
        filtre = filters.byTransport('voltron', ipVersion=6)
        self.assertTrue(filtre(self.bridge))

    def test_byTransport_with_transport_ipv6_filtering_by_ipv4(self):
        """A bridge with an IPv6 voltron transport should cause
        byTransport('voltron') to return True.
        """
        self.addIPv6VoltronPT()
        filtre = filters.byTransport('voltron')
        self.assertFalse(filtre(self.bridge))

    def test_byTransport_no_transports(self):
        """A bridge without any transports should cause
        byTransport('voltron') to return False.
        """
        filtre = filters.byTransport('voltron')
        self.assertFalse(filtre(self.bridge))

    def test_byTransport_vanilla_ipv4(self):
        """byTransport() without namimg a transport to filter by should just
        return the bridge's IPv4 address.
        """
        filtre = filters.byTransport()
        self.assertTrue(filtre(self.bridge))

    def test_byTransport_vanilla_ipv6(self):
        """byTranspfort(ipVersion=6) without namimg a transport to filter by
        should just return the bridge's IPv4 address.
        """
        self.bridge.orAddresses = [(ipaddr.IPv6Address('2006:3333::3333'), 3333, 6)]
        filtre = filters.byTransport(ipVersion=6)
        self.assertTrue(filtre(self.bridge))

    def test_byTransport_wrong_transport(self):
        """A bridge with only a Voltron transport should cause
        byTransport('obfs3') to return False.
        """
        self.addIPv4VoltronPT()
        filtre = filters.byTransport('obfs3')
        self.assertFalse(filtre(self.bridge))

    def test_byNotBlockedIn_no_countryCode_with_transport_ipv4(self):
        """A bridge with an IPv4 voltron transport should cause
        byNotBlockedIn('voltron') to return True (because it calls
        filters.byTransport).
        """
        self.addIPv4VoltronPT()
        filtre = filters.byNotBlockedIn(None, methodname='voltron')
        self.assertTrue(filtre(self.bridge))

    def test_byNotBlockedIn_no_countryCode_with_transport_ipv6(self):
        """A bridge with an IPv6 voltron transport should cause
        byNotBlockedIn('voltron') to return True (because it calls
        filters.byTransport).
        """
        self.addIPv6VoltronPT()
        filtre = filters.byNotBlockedIn(None, methodname='voltron', ipVersion=6)
        self.assertTrue(filtre(self.bridge))

    def test_byNotBlockedIn_with_transport_ipv4(self):
        """A bridge with an IPv4 voltron transport should cause
        byNotBlockedIn('voltron') to return True.
        """
        self.addIPv4VoltronPT()
        filtre = filters.byNotBlockedIn('CN', methodname='voltron')
        self.assertTrue(filtre(self.bridge))

    def test_byNotBlockedIn_with_transport_ipv4_blocked(self):
        """A bridge with an IPv4 voltron transport which is blocked should
        cause byNotBlockedIn('voltron') to return False.
        """
        self.addIPv4VoltronPT()
        self.bridge.setBlockedIn('CN')
        filtre = filters.byNotBlockedIn('CN', methodname='voltron')
        self.assertFalse(filtre(self.bridge))

    def test_byNotBlockedIn_with_transport_ipv6(self):
        """A bridge with an IPv6 voltron transport should cause
        byNotBlockedIn('voltron') to return True.
        """
        self.addIPv6VoltronPT()
        filtre = filters.byNotBlockedIn('cn', 'voltron', ipVersion=6)
        self.assertTrue(filtre(self.bridge))

    def test_byNotBlockedIn_with_transport_ipv4_not_blocked_ipv4(self):
        """A bridge with an IPv6 voltron transport which is not blocked in China
        should cause byNotBlockedIn('cn', 'voltron') to return False, because
        the IP version is wrong.
        """
        self.addIPv6VoltronPT()
        filtre = filters.byNotBlockedIn('cn', 'voltron')
        self.assertFalse(filtre(self.bridge))

    def test_byNotBlockedIn_with_transport_ipv6_blocked(self):
        """A bridge with an IPv6 voltron transport which is blocked should
        cause byNotBlockedIn('voltron') to return False.
        """
        self.addIPv6VoltronPT()
        self.bridge.setBlockedIn('CN')
        filtre = filters.byNotBlockedIn('cn', 'voltron', ipVersion=6)
        self.assertFalse(filtre(self.bridge))

    def test_byNotBlockedIn_no_countryCode_no_transports(self):
        """A bridge without any transports should cause
        byNotBlockedIn('voltron') to return False (because it calls
        filters.byTransport('voltron')).
        """
        filtre = filters.byNotBlockedIn(None, methodname='voltron')
        self.assertFalse(filtre(self.bridge))

    def test_byNotBlockedIn_no_transports(self):
        """A bridge without any transports should cause
        byNotBlockedIn('cn', 'voltron') to return False.
        """
        filtre = filters.byNotBlockedIn('cn', methodname='voltron')
        self.assertFalse(filtre(self.bridge))

    def test_byNotBlockedIn_no_transports_blocked(self):
        """A bridge without any transports which is also blocked should cause
        byNotBlockedIn('voltron') to return False.
        """
        self.bridge.setBlockedIn('cn')
        filtre = filters.byNotBlockedIn('cn', methodname='voltron')
        self.assertFalse(filtre(self.bridge))

    def test_byNotBlockedIn_wrong_transport(self):
        """A bridge with only a Voltron transport should cause
        byNotBlockedIn('obfs3') to return False.
        """
        self.addIPv4VoltronPT()
        filtre = filters.byNotBlockedIn('cn', methodname='obfs3')
        self.assertFalse(filtre(self.bridge))

    def test_byNotBlockedIn_ipv5(self):
        """Calling byNotBlockedIn([…], ipVersion=5) should default to IPv4."""
        self.bridge.setBlockedIn('ru')
        filtre = filters.byNotBlockedIn('cn', ipVersion=5)
        self.assertTrue(filtre(self.bridge))

    def test_byNotBlockedIn_vanilla_not_blocked(self):
        """Calling byNotBlockedIn('vanilla') should return the IPv4 vanilla
        address, if it is not blocked.
        """
        self.bridge.setBlockedIn('ru')
        filtre = filters.byNotBlockedIn('cn', methodname='vanilla')
        self.assertTrue(filtre(self.bridge))

    def test_byNotBlockedIn_vanilla_not_blocked_ipv6(self):
        """Calling byNotBlockedIn('vanilla', ipVersion=6) should not return the
        IPv4 vanilla address, even if it is not blocked, because it has the
        wrong IP version.
        """
        self.bridge.setBlockedIn('ru')
        filtre = filters.byNotBlockedIn('cn', methodname='vanilla', ipVersion=6)
        self.assertFalse(filtre(self.bridge))

    def test_byNotBlockedIn_vanilla_blocked(self):
        """Calling byNotBlockedIn('vanilla') should not return the IPv4 vanilla
        address, if it is blocked.
        """
        self.bridge.setBlockedIn('ru')
        filtre = filters.byNotBlockedIn('ru', methodname='vanilla')
        self.assertFalse(filtre(self.bridge))
