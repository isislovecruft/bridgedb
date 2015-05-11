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

"""A Distributor that hands out bridges through a web interface."""

from __future__ import print_function

import ipaddr
import logging
import math

import bridgedb.Storage

from bridgedb import proxy
from bridgedb import strings
from bridgedb.crypto import getHMAC
from bridgedb.crypto import getHMACFunc
from bridgedb.distribute import Distributor
from bridgedb.filters import byIPv4
from bridgedb.filters import byIPv6
from bridgedb.filters import byFilters
from bridgedb.filters import bySubring
from bridgedb.filters import byTransport
from bridgedb.hashring import ConstrainedHashring
from bridgedb.hashring import Hashring
from bridgedb.hashring import ProportionalHashring


class HTTPSDistributor(Distributor):
    """A Distributor that hands out bridges based on the IP address of an
    incoming request and the current time period.

    The bridges which are distributed to a client by this :class:`Distributor`
    are deterministically computed via relation to the interval in which the
    client's request occurred, as well as the subnet of the client's IP
    address.

    .. note:: For an explanation of how **subnet** is determined, see
        :staticmethod:`getSubnet`.

    :type proxies: :class:`~bridgedb.proxies.ProxySet`
    :ivar proxies: All known proxies, which we treat differently. See
        :param:`proxies`.
    :type hashring: :class:`bridgedb.hashring.ProportionalHashring`
    :ivar hashring: A hashring that assigns bridges to subrings with fixed
        proportions. Used to assign bridges into the subrings of this
        distributor.
    """

    def __init__(self, totalSubrings, key, proxies=None, constraints=None):
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
        :param list constraints: A list of 3-tuples, where each tuple
            contains::
                (CATEGORY, VALUE, COUNT)
            where:
              * CATEGORY is one of the keys in bridgedb.hashring.CONSTRAINTS,
                i.e. currently one of "FLAG", "PORT", "COUNTRY", or
                "NOT_COUNTRY".
              * VALUE is the arguments to pass to the constraint function,
                i.e. for the "FLAG" constraint, this should be "Stable" or
                "Running", and for the "PORT" constraint this should be a port
                number like 443 or 9001.
              * COUNT is an integer specifying the number of bridges, per
                answer, which should meet this constraint.
        """
        super(HTTPSDistributor, self).__init__(key)
        self.totalSubrings = totalSubrings
        self.constraints = constraints

        self._proxySubring = None
        self._nonProxySubring = None
        self._cacheSize = int(math.e * self.totalSubrings)
        self._subringHMAC = getHMACFunc(getHMAC(key, "Subnets-To-Subrings"))
        self.hashring = ProportionalHashring(getHMAC(key, "Hashring"))
        self.hashring.setCacheSize(self._cacheSize)
        self.hashring.name = "HTTPS"

        if proxies:
            logging.info("Added known proxies to HTTPS distributor...")
            self.proxies = proxies
        else:
            logging.warn("No known proxies were added to HTTPS distributor!")
            self.proxies = proxy.ProxySet()

        self.buildHashrings()
        self.name = 'HTTPS'

    @property
    def nonProxySubring(self):
        if not self._nonProxySubring:
            for subring in self.hashring.subrings:
                if subring.name == "{0} (Non-Proxy)".format(self.name):
                    self._nonProxySubring = subring
        return self._nonProxySubring

    @property
    def proxySubring(self):
        if not self._proxySubring:
            for subring in self.hashring.subrings:
                if subring.name == "{0} (Proxy)".format(self.name):
                    self._proxySubring = subring
        return self._proxySubring

    def buildHashrings(self):
        if self.hashring.subrings:
            logging.debug(("But the HTTPS Distributor's hashrings were "
                           "already built!"))
            return

        # Subring names/purposes to their relative proportions
        subrings = {"Non-Proxy": 3}

        if self.proxies:
            logging.debug("Allocating some bridges to proxy users...")
            subrings["Proxy"] = 1

        for name, proportion in subrings.items():
            subkey = getHMAC(self.hashring.key, "%s-Subring" % name)
            subring = Hashring(subkey)
            for index in range(self.totalSubrings):
                assigned = index + 1
                #subkey = getHMAC(subkey, "%s-Subring-%d-" % (name, assigned))
                hmac = getHMACFunc(subkey)
                constraint = bySubring(hmac, assigned, self.totalSubrings)
                subsubring = ConstrainedHashring(subkey, constraint)
                subsubring.setCacheSize(self.hashring.cache.size)
                subring.addSubring(subsubring)
            self.hashring.addSubring(subring, name, proportion=proportion)

        logging.info(self.hashring.tree())

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

    def findSubringFor(self, client, usingProxy=False):
        """Determine the correct subhashring for a client, based upon the
        **subnet**.

        :param str client: The client's IP address.
        :param bool usingProxy: Set to ``True`` if the client was using one of
            the known :data:`proxies`.
        """
        if usingProxy:
            subring = self.proxySubring
        else:
            subring = self.nonProxySubring

        subnet = self.getSubnet(client, usingProxy)
        index = int(self._subringHMAC(subnet)[:8], 16) % self.totalSubrings
        return subring.subrings[index]

    def getBridges(self, bridgeRequest, interval):
        """Return a list of bridges to give to a user.

        :type bridgeRequest: :class:`bridgedb.https.request.HTTPSBridgeRequest`
        :param bridgeRequest: A :class:`~bridgedb.bridgerequest.BridgeRequestBase`
            with the :data:`~bridgedb.bridgerequest.BridgeRequestBase.client`
            attribute set to a string containing the client's IP address.
        :param str interval: The time period when we got this request.  This
            can be any string, so long as it changes with every period.
        :rtype: list
        :return: A list of :class:`~bridgedb.bridges.Bridge`s to include in
            the response. See
            :meth:`bridgedb.https.server.WebResourceBridges.getBridgeRequestAnswer`
            for an example of how this is used.
        """
        logging.info("Attempting to get bridges for %s..." % bridgeRequest.client)

        if not len(self.hashring):
            logging.warn("Bailing! Hashring has zero bridges!")
            return []

        usingProxy = False

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
        subring = self.findSubringFor(bridgeRequest.client, usingProxy)
        position = self.getHashringPosition(interval, subnet)
        filters = bridgeRequest.filters

        logging.debug("Client request within time interval: %s" % interval)
        logging.debug("Bridge filters: %s" % ", ".join([f.name for f in filters]))
        logging.debug("Assigned client to sub-hashring: %s" % subring.name)
        logging.debug("Assigned client to sub-hashring position: %s" % position.encode('hex'))
        logging.debug("Total bridges in sub-hashring: %d" % len(subring))

        filtered = subring.reduce(*filters)
        answer = filtered.retrieve(position, self.bridgesPerResponse(filtered))

        logging.debug("Total filtered bridges: %d" % len(filtered))

        return answer

    def regenerateCaches(self):
        """Regenerate this distributor's hashring and sub-hashring caches with
        any new bridges which should belong in them.

        The hashring structure for this distributor is influenced by the
        ``N_IP_CLUSTERS`` configuration option, which is stored in
        :data:`totalSubrings`.

        For an :class:`HTTPSDistributor` with 500 bridges, no Tor Exit relays
        or other known proxies stored in :data:`proxies`, and
        ``N_IP_CLUSTERS = 3``, the hashring structure and distribution of
        bridges would be::

                               ProportionalHashring [500]
                                         (0:4)
                  Hashring [0]                           Hashring [500]
            ConstrainedHashring [0]                ConstrainedHashring [145]
            ConstrainedHashring [0]                ConstrainedHashring [181]
            ConstrainedHashring [0]                ConstrainedHashring [174]

        Whereas, if it had stored :data:`proxies`, the hashring structure and
        distribution of bridges would look something like::

                               ProportionalHashring [500]
                                         (1:4)
                 Hashring [106]                          Hashring [394]
           ConstrainedHashring [37]                ConstrainedHashring [131]
           ConstrainedHashring [34]                ConstrainedHashring [136]
           ConstrainedHashring [35]                ConstrainedHashring [127]

        Within each :class:`ConstrainedHashring` is an LRU
        :class:`~bridgedb.util.Cache` that is configured to retain filtered
        copies of its :class:`ConstrainedHashring` as a new :class:`Hashring`,
        the latter of which only contains items from the
        :class:`ConstrainedHashring` which passed some set of filters.  This
        can be used to accelerate answers to common types of bridge requests,
        i.e. "only bridges which are IPv6" or "only bridges which have the
        ``Stable`` flag", etc.
        """
        logging.info("Regenerating caches for %s distributor hashrings..." %
                     self.name)

        filters = [byIPv4, byIPv6]
        defaultTransport = strings._getDefaultTransport()
        if defaultTransport:
            filters.append(byTransport(defaultTransport))

        for subring in self.hashring.subrings:
            for subsubring in subring.subrings:
                for filtre in filters:
                    subsubring.addToCache(filtre)
