# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_https_distributor -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Nick Mathewson
#           Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           Matthew Finkel 0x017DD169EA793BE2 <sysrqb@torproject.org>
# :copyright: (c) 2013-2015, Isis Lovecruft
#             (c) 2013-2015, Matthew Finkel
#             (c) 2007-2015, The Tor Project, Inc.
# :license: see LICENSE for licensing information

"""
bridgedb.https.distributor
==========================

A Distributor that hands out bridges through a web interface.

.. inheritance-diagram:: HTTPSDistributor
    :parts: 1
"""

import ipaddr
import logging

import bridgedb.Storage

from bridgedb import proxy
from bridgedb.Bridges import BridgeRing
from bridgedb.Bridges import FilteredBridgeSplitter
from bridgedb.crypto import getHMAC
from bridgedb.crypto import getHMACFunc
from bridgedb.distribute import Distributor
from bridgedb.filters import byIPv4
from bridgedb.filters import byIPv6
from bridgedb.filters import byFilters
from bridgedb.filters import bySubring


class HTTPSDistributor(Distributor):
    """A Distributor that hands out bridges based on the IP address of an
    incoming request and the current time period.

    :type proxies: :class:`~bridgedb.proxies.ProxySet`
    :ivar proxies: All known proxies, which we treat differently. See
        :param:`proxies`.
    :type hashring: :class:`bridgedb.Bridges.FilteredBridgeSplitter`
    :ivar hashring: A hashring that assigns bridges to subrings with fixed
        proportions. Used to assign bridges into the subrings of this
        distributor.
    """

    def __init__(self, totalSubrings, key, proxies=None, answerParameters=None):
        """Create a Distributor that decides which bridges to distribute based
        upon the client's IP address and the current time.

        :param int totalSubrings: The number of subhashrings to group clients
            into. Note that if ``PROXY_LIST_FILES`` is set in bridgedb.conf,
            then the actual number of clusters is one higher than
            ``totalSubrings``, because the set of all known open proxies is
            given its own subhashring.
        :param bytes key: The master HMAC key for this distributor. All added
            bridges are HMACed with this key in order to place them into the
            hashrings.
        :type proxies: :class:`~bridgedb.proxy.ProxySet`
        :param proxies: A :class:`bridgedb.proxy.ProxySet` containing known
            Tor Exit relays and other known proxies.  These will constitute
            the extra cluster, and any client requesting bridges from one of
            these **proxies** will be distributed bridges from a separate
            subhashring that is specific to Tor/proxy users.
        :type answerParameters: :class:`bridgedb.Bridges.BridgeRingParameters`
        :param answerParameters: A mechanism for ensuring that the set of
            bridges that this distributor answers a client with fit certain
            parameters, i.e. that an answer has "at least two obfsproxy
            bridges" or "at least one bridge on port 443", etc.
        """
        super(HTTPSDistributor, self).__init__(key)
        self.totalSubrings = totalSubrings
        self.answerParameters = answerParameters

        if proxies:
            logging.info("Added known proxies to HTTPS distributor...")
            self.proxies = proxies
            self.totalSubrings += 1
            self.proxySubring = self.totalSubrings
        else:
            logging.warn("No known proxies were added to HTTPS distributor!")
            self.proxies = proxy.ProxySet()
            self.proxySubring = 0

        self.ringCacheSize = self.totalSubrings * 3

        key2 = getHMAC(key, "Assign-Bridges-To-Rings")
        key3 = getHMAC(key, "Order-Areas-In-Rings")
        key4 = getHMAC(key, "Assign-Areas-To-Rings")

        self._clientToPositionHMAC = getHMACFunc(key3, hex=False)
        self._subnetToSubringHMAC = getHMACFunc(key4, hex=True)
        self.hashring = FilteredBridgeSplitter(key2, self.ringCacheSize)
        self.name = 'HTTPS'
        logging.debug("Added %s to %s distributor." %
                      (self.hashring.__class__.__name__, self.name))

    def bridgesPerResponse(self, hashring=None):
        return super(HTTPSDistributor, self).bridgesPerResponse(hashring)

    @classmethod
    def getSubnet(cls, ip, usingProxy=False, proxySubnets=4):
        """Map all clients whose **ip**s are within the same subnet to the same
        arbitrary string.

        .. hint:: For non-proxy IP addresses, any two IPv4 addresses within
            the same ``/16`` subnet, or any two IPv6 addresses in the same
            ``/32`` subnet, will get the same string.

        Subnets for this distributor are grouped into the number of rings
        specified by the ``N_IP_CLUSTERS`` configuration option, such that
        Alice (with the address ``1.2.3.4`` and Bob (with the address
        ``1.2.178.234``) are placed within the same cluster, but Carol (with
        address ``1.3.11.33``) *might* end up in a different cluster.

        >>> from bridgedb.https.distributor import HTTPSDistributor
        >>> HTTPSDistributor.getSubnet('1.2.3.4')
        '1.2.0.0/16'
        >>> HTTPSDistributor.getSubnet('1.2.211.154')
        '1.2.0.0/16'
        >>> HTTPSDistributor.getSubnet('2001:f::bc1:b13:2808')
        '2001:f::/32'
        >>> HTTPSDistributor.getSubnet('2a00:c98:2030:a020:2::42')
        '2a00:c98::/32'

        :param str ip: A string representing an IPv4 or IPv6 address.
        :param bool usingProxy: Set to ``True`` if the client was using one of
            the known :data:`proxies`.
        :param int proxySubnets: Place Tor/proxy users into this number of
            "subnet" groups.  This means that no matter how many different Tor
            Exits or proxies a client uses, the most they can ever get is
            **proxySubnets** different sets of bridge lines (per interval).
            This parameter only has any effect when **usingProxy** is ``True``.
        :rtype: str
        :returns: The appropriately sized CIDR subnet representation of the **ip**.
        """
        if not usingProxy:
            # We aren't using bridgedb.parse.addr.isIPAddress(ip,
            # compressed=False) here because adding the string "False" into
            # the map would land any and all clients whose IP address appeared
            # to be invalid at the same position in a hashring.
            address = ipaddr.IPAddress(ip)
            if address.version == 6:
                truncated = ':'.join(address.exploded.split(':')[:2])
                subnet = str(ipaddr.IPv6Network(truncated + "::/32"))
            else:
                truncated = '.'.join(address.exploded.split('.')[:2])
                subnet = str(ipaddr.IPv4Network(truncated + '.0.0/16'))
        else:
            group = (int(ipaddr.IPAddress(ip)) % 4) + 1
            subnet = "proxy-group-%d" % group

        logging.debug("Client IP was within area: %s" % subnet)
        return subnet

    def mapSubnetToSubring(self, subnet, usingProxy=False):
        """Determine the correct subhashring for a client, based upon the
        **subnet**.

        :param str subnet: The subnet which contains the client's IP.  See
            :staticmethod:`getSubnet`.
        :param bool usingProxy: Set to ``True`` if the client was using one of
            the known :data:`proxies`.
        """
        # If the client wasn't using a proxy, select the client's subring
        # based upon the client's subnet (modulo the total subrings):
        if not usingProxy:
            mod = self.totalSubrings
            # If there is a proxy subring, don't count it for the modulus:
            if self.proxySubring:
                mod -= 1
            return (int(self._subnetToSubringHMAC(subnet)[:8], 16) % mod) + 1
        else:
            return self.proxySubring

    def mapClientToHashringPosition(self, interval, subnet):
        """Map the client to a position on a (sub)hashring, based upon the
        **interval** which the client's request occurred within, as well as
        the **subnet** of the client's IP address.

        .. note:: For an explanation of how **subnet** is determined, see
            :staticmethod:`getSubnet`.

        :param str interval: The interval which this client's request for
            bridges took place within.
        :param str subnet: A string representing the subnet containing the
            client's IP address.
        :rtype: int
        :returns: The results of keyed HMAC, which should determine the
            client's position in a (sub)hashring of bridges (and thus
            determine which bridges they receive).
        """
        position = "<%s>%s" % (interval, subnet)
        mapping = self._clientToPositionHMAC(position)
        return mapping

    def prepopulateRings(self):
        """Prepopulate this distributor's hashrings and subhashrings with
        bridges.

        The hashring structure for this distributor is influenced by the
        ``N_IP_CLUSTERS`` configuration option, as well as the number of
        ``PROXY_LIST_FILES``.

        Essentially, :data:`totalSubrings` is set to the specified
        ``N_IP_CLUSTERS``.  All of the ``PROXY_LIST_FILES``, plus the list of
        Tor Exit relays (downloaded into memory with :script:`get-tor-exits`),
        are stored in :data:`proxies`, and the latter is added as an
        additional cluster (such that :data:`totalSubrings` becomes
        ``N_IP_CLUSTERS + 1``).  The number of subhashrings which this
        :class:`Distributor` has active in its hashring is then
        :data:`totalSubrings`, where the last cluster is reserved for all
        :data:`proxies`.

        As an example, if BridgeDB was configured with ``N_IP_CLUSTERS=4`` and
        ``PROXY_LIST_FILES=["open-socks-proxies.txt"]``, then the total number
        of subhashrings is five — four for the "clusters", and one for the
        :data:`proxies`. Thus, the resulting hashring-subhashring structure
        would look like:

        +------------------+---------------------------------------------------+-------------+
        |                  |               Directly connecting users           | Tor / known |
        |                  |                                                   | proxy users |
        +------------------+------------+------------+------------+------------+-------------+
        | Clusters         | Cluster-1  | Cluster-2  | Cluster-3  | Cluster-4  | Cluster-5   |
        +==================+============+============+============+============+=============+
        | Subhashrings     |            |            |            |            |             |
        | (total, assigned)| (5,1)      | (5,2)      | (5,3)      | (5,4)      | (5,5)       |
        +------------------+------------+------------+------------+------------+-------------+
        | Filtered         | (5,1)-IPv4 | (5,2)-IPv4 | (5,3)-IPv4 | (5,4)-IPv4 | (5,5)-IPv4  |
        | Subhashrings     |            |            |            |            |             |
        | bBy requested    +------------+------------+------------+------------+-------------+
        | bridge type)     | (5,1)-IPv6 | (5,2)-IPv6 | (5,3)-IPv6 | (5,4)-IPv6 | (5,5)-IPv6  |
        |                  |            |            |            |            |             |
        +------------------+------------+------------+------------+------------+-------------+

        The "filtered subhashrings" are essentially filtered copies of their
        respective subhashring, such that they only contain bridges which
        support IPv4 or IPv6, respectively.  Additionally, the contents of
        ``(5,1)-IPv4`` and ``(5,1)-IPv6`` sets are *not* disjoint.

        Thus, in this example, we end up with **10 total subhashrings**.
        """
        logging.info("Prepopulating %s distributor hashrings..." % self.name)

        for filterFn in [byIPv4, byIPv6]:
            for subring in range(1, self.totalSubrings + 1):
                filters = self._buildHashringFilters([filterFn,], subring)
                key1 = getHMAC(self.key, "Order-Bridges-In-Ring-%d" % subring)
                ring = BridgeRing(key1, self.answerParameters)
                # For consistency with previous implementation of this method,
                # only set the "name" for "clusters" which are for this
                # distributor's proxies:
                if subring == self.proxySubring:
                    ring.setName('{0} Proxy Ring'.format(self.name))
                self.hashring.addRing(ring, filters, byFilters(filters),
                                      populate_from=self.hashring.bridges)

    def insert(self, bridge):
        """Assign a bridge to this distributor."""
        self.hashring.insert(bridge)

    def _buildHashringFilters(self, previousFilters, subring):
        f = bySubring(self.hashring.hmac, subring, self.totalSubrings)
        previousFilters.append(f)
        return frozenset(previousFilters)

    def getBridges(self, bridgeRequest, interval):
        """Return a list of bridges to give to a user.

        :type bridgeRequest: :class:`bridgedb.https.request.HTTPSBridgeRequest`
        :param bridgeRequest: A :class:`~bridgedb.bridgerequest.BridgeRequestBase`
            with the :data:`~bridgedb.bridgerequest.BridgeRequestBase.client`
            attribute set to a string containing the client's IP address.
        :param str interval: The time period when we got this request.  This
            can be any string, so long as it changes with every period.
        :rtype: list
        :return: A list of :class:`~bridgedb.Bridges.Bridge`s to include in
            the response. See
            :meth:`bridgedb.https.server.WebResourceBridges.getBridgeRequestAnswer`
            for an example of how this is used.
        """
        logging.info("Attempting to get bridges for %s..." % bridgeRequest.client)

        if not len(self.hashring):
            logging.warn("Bailing! Hashring has zero bridges!")
            return []

        usingProxy = False

        # First, check if the client's IP is one of the known :data:`proxies`:
        if bridgeRequest.client in self.proxies:
            # The tag is a tag applied to a proxy IP address when it is added
            # to the bridgedb.proxy.ProxySet. For Tor Exit relays, the default
            # is 'exit_relay'. For other proxies loaded from the
            # PROXY_LIST_FILES config option, the default tag is the full
            # filename that the IP address originally came from.
            usingProxy = True
            tag = self.proxies.getTag(bridgeRequest.client)
            logging.info("Client was from known proxy (tag: %s): %s" %
                         (tag, bridgeRequest.client))

        subnet = self.getSubnet(bridgeRequest.client, usingProxy)
        subring = self.mapSubnetToSubring(subnet, usingProxy)
        position = self.mapClientToHashringPosition(interval, subnet)
        filters = self._buildHashringFilters(bridgeRequest.filters, subring)

        logging.debug("Client request within time interval: %s" % interval)
        logging.debug("Assigned client to subhashring %d/%d" % (subring, self.totalSubrings))
        logging.debug("Assigned client to subhashring position: %s" % position.encode('hex'))
        logging.debug("Total bridges: %d" % len(self.hashring))
        logging.debug("Bridge filters: %s" % ' '.join([x.func_name for x in filters]))

        # Check wheth we have a cached copy of the hashring:
        if filters in self.hashring.filterRings.keys():
            logging.debug("Cache hit %s" % filters)
            _, ring = self.hashring.filterRings[filters]
        # Otherwise, construct a new hashring and populate it:
        else:
            logging.debug("Cache miss %s" % filters)
            key1 = getHMAC(self.key, "Order-Bridges-In-Ring-%d" % subring)
            ring = BridgeRing(key1, self.answerParameters)
            self.hashring.addRing(ring, filters, byFilters(filters),
                                  populate_from=self.hashring.bridges)

        # Determine the appropriate number of bridges to give to the client:
        returnNum = self.bridgesPerResponse(ring)
        answer = ring.getBridges(position, returnNum)

        return answer
