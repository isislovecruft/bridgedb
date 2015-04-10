# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_Dist -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Nick Mathewson
#           Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           Matthew Finkel 0x017DD169EA793BE2 <sysrqb@torproject.org>
# :copyright: (c) 2013-2015, Isis Lovecruft
#             (c) 2013-2015, Matthew Finkel
#             (c) 2007-2015, The Tor Project, Inc.
# :license: 3-Clause BSD, see LICENSE for licensing information

"""This module has functions to decide which bridges to hand out to whom."""

import ipaddr
import logging
import re
import time

import bridgedb.Bridges
import bridgedb.Storage

from bridgedb.crypto import getHMAC
from bridgedb.crypto import getHMACFunc
from bridgedb.Filters import filterAssignBridgesToRing
from bridgedb.Filters import filterBridgesByRules
from bridgedb.Filters import filterBridgesByIP4
from bridgedb.Filters import filterBridgesByIP6
from bridgedb.parse import addr
from bridgedb.parse.addr import UnsupportedDomain
from bridgedb.safelog import logSafely


MAX_EMAIL_RATE = 3*3600

class IgnoreEmail(addr.BadEmail):
    """Raised when we get requests from this address after rate warning."""

class TooSoonEmail(addr.BadEmail):
    """Raised when we got a request from this address too recently."""

class EmailRequestedHelp(Exception):
    """Raised when a client has emailed requesting help."""

class EmailRequestedKey(Exception):
    """Raised when an incoming email requested a copy of our GnuPG keys."""


def uniformMap(ip):
    """Map an IP to an arbitrary 'area' string, such that any two IPv4
    addresses in the same ``/16`` subnet, or any two IPv6 addresses in the
    same ``/32`` subnet, get the same string.

    >>> from bridgedb import Dist
    >>> Dist.uniformMap('1.2.3.4')
    '1.2.0.0/16'
    >>> Dist.uniformMap('1.2.211.154')
    '1.2.0.0/16'
    >>> Dist.uniformMap('2001:f::bc1:b13:2808')
    '2001:f::/32'
    >>> Dist.uniformMap('2a00:c98:2030:a020:2::42')
    '2a00:c98::/32'

    :param str ip: A string representing an IPv4 or IPv6 address.
    :rtype: str
    :returns: The appropriately sized CIDR subnet representation of the **ip**.
    """
    # We aren't using bridgedb.parse.addr.isIPAddress(ip, compressed=False)
    # here because adding the string "False" into the map would land any and
    # all clients whose IP address appeared to be invalid at the same position
    # in a hashring.
    address = ipaddr.IPAddress(ip)
    if address.version == 6:
        truncated = ':'.join(address.exploded.split(':')[:2])
        subnet = str(ipaddr.IPv6Network(truncated + "::/32"))
        return subnet
    else:
        truncated = '.'.join(address.exploded.split('.')[:2])
        subnet = str(ipaddr.IPv4Network(truncated + '.0.0/16'))
        return subnet

def getNumBridgesPerAnswer(ring, max_bridges_per_answer=3):
    if len(ring) < 20:
        n_bridges_per_answer = 1
    if 20 <= len(ring) < 100:
        n_bridges_per_answer = min(2, max_bridges_per_answer)
    if len(ring) >= 100:
        n_bridges_per_answer = max_bridges_per_answer

    logging.debug("Returning %d bridges from ring of len: %d" %
                  (n_bridges_per_answer, len(ring)))

    return n_bridges_per_answer


class Distributor(object):
    """Distributes bridges to clients."""

    def __init__(self):
        super(Distributor, self).__init__()

    def setDistributorName(self, name):
        """Set a **name** for identifying this distributor.

        This is used to identify the distributor in the logs; the **name**
        doesn't necessarily need to be unique. The hashrings created for this
        distributor will be named after this distributor's name in
        :meth:`propopulateRings`, and any sub hashrings of each of those
        hashrings will also carry that name.

        >>> from bridgedb import Dist
        >>> ipDist = Dist.IPBasedDistributor(Dist.uniformMap,
        ...                                  5,
        ...                                  'fake-hmac-key')
        >>> ipDist.setDistributorName('HTTPS Distributor')
        >>> ipDist.prepopulateRings()
        >>> hashrings = ipDist.splitter.filterRings
        >>> firstSubring = hashrings.items()[0][1][1]
        >>> assert firstSubring.name

        :param str name: A name for this distributor.
        """
        self.name = name
        self.splitter.distributorName = name


class IPBasedDistributor(Distributor):
    """A Distributor that hands out bridges based on the IP address of an
    incoming request and the current time period.

    :ivar areaOrderHmac: An HMAC function used to order areas within rings.
    :ivar areaClusterHmac: An HMAC function used to assign areas to rings.
    :ivar list rings: A list of :class:`bridgedb.Bridges.BridgeHolder`
        hashrings, one for each area in the ``areaMapper``. Every inserted
        bridge will go into one of these rings, and every area is associated
        with one.
    :ivar categories: DOCDOC See :param:`proxySets`.
    :type splitter: :class:`bridgedb.Bridges.FixedBridgeSplitter`
    :ivar splitter: A hashring that assigns bridges to subrings with fixed
        proportions. Used to assign bridges into the subrings of this
        distributor.
    """

    def __init__(self, areaMapper, numberOfClusters, key,
                 proxySets=None, answerParameters=None):
        """Create a Distributor that decides which bridges to distribute based
        upon the client's IP address and the current time.

        :type areaMapper: callable
        :param areaMapper: A function that maps IP addresses arbitrarily to
            strings, such that addresses which map to identical strings are
            considered to be in the same "area" (for some arbitrary definition
            of "area"). See :func:`bridgedb.Dist.uniformMap` for an example.
        :param integer numberOfClusters: The number of clusters to group IP addresses
            into. Note that if PROXY_LIST_FILES is set in bridgedb.conf, then
            the actual number of clusters is one higher than ``numberOfClusters``,
            because the set of known open proxies constitutes its own
            category.
            DOCDOC What exactly does a cluster *do*?
        :param bytes key: The master HMAC key for this distributor. All added
            bridges are HMACed with this key in order to place them into the
            hashrings.
        :type proxySets: iterable or None
        :param proxySets: DOCDOC
        :type answerParameters: :class:`bridgedb.Bridges.BridgeRingParameters`
        :param answerParameters: A mechanism for ensuring that the set of
            bridges that this distributor answers a client with fit certain
            parameters, i.e. that an answer has "at least two obfsproxy
            bridges" or "at least one bridge on port 443", etc.
        """
        self.areaMapper = areaMapper
        self.numberOfClusters = numberOfClusters
        self.answerParameters = answerParameters

        if not proxySets:
            proxySets = []
        if not answerParameters:
            answerParameters = []
        self.rings = []

        self.categories = []
        for c in proxySets:
            self.categories.append(c)

        key2 = getHMAC(key, "Assign-Bridges-To-Rings")
        key3 = getHMAC(key, "Order-Areas-In-Rings")
        self.areaOrderHmac = getHMACFunc(key3, hex=False)
        key4 = getHMAC(key, "Assign-Areas-To-Rings")
        self.areaClusterHmac = getHMACFunc(key4, hex=True)

        # add splitter and cache the default rings
        # plus leave room for dynamic filters
        #
        # XXX Why is the "extra room" hardcoded to be 5? Shouldn't it be some
        #     fraction of the number of clusters/categories? --isis
        ring_cache_size  = self.numberOfClusters + len(proxySets) + 5
        self.splitter = bridgedb.Bridges.FilteredBridgeSplitter(
            key2, max_cached_rings=ring_cache_size)
        logging.debug("Added splitter %s to IPBasedDistributor."
                      % self.splitter.__class__)

        self.setDistributorName('HTTPS')

    def prepopulateRings(self):
        """Prepopulate this distributor's hashrings and subhashrings with
        bridges.

        The hashring structure for this distributor is influenced by the
        ``N_IP_CLUSTERS`` configuration option, as well as the number of
        ``PROXY_LIST_FILES``.  Essentially, :data:`numberOfClusters` is set to the
        specified ``N_IP_CLUSTERS``.  The ``PROXY_LIST_FILES`` (plus the
        :class:`bridgedb.proxy.ProxySet` for the Tor Exit list downloaded into
        memory with :script:`get-tor-exits`) are stored in :data:`categories`.

        The number of subhashrings which this :class:`Distributor` has active
        in its hashring is then the :data:`numberOfClusters` plus the number of
        :data:`categories`.

        As an example, if BridgeDB was configured with ``N_IP_CLUSTERS=4`` and
        ``PROXY_LIST_FILES=["open-socks-proxies.txt"]``, then the total number
        of subhashrings is six — four for the "clusters", and two
        "categories": one for everything contained within the
        ``"open-socks-proxies.txt"`` file and the other for the downloaded
        list of Tor Exits.  Thus, the resulting hashring-subhashring structure
        would look like:

        +------------------+---------------------------------------------------+-------------------------+
        |                  |               Directly connecting users           | Tor / known proxy users |
        +------------------+------------+------------+------------+------------+------------+------------+
        | Clusters /       | Cluster-1  | Cluster-2  | Cluster-3  | Cluster-4  | Cat-1      | Cat-2      |
        | Categories       |            |            |            |            |            |            |
        +==================+============+============+============+============+============+============+
        | Subhashrings     |            |            |            |            |            |            |
        | (total, assigned)| (6,0)      | (6,1)      | (6,2)      | (6,3)      | (6,4)      | (6,5)      |
        +------------------+------------+------------+------------+------------+------------+------------+
        | Filtered         | (6,0)-IPv4 | (6,1)-IPv4 | (6,2)-IPv4 | (6,3)-IPv4 | (6,4)-IPv4 | (6,5)-IPv4 |
        | Subhashrings     |            |            |            |            |            |            |
        | bBy requested    +------------+------------+------------+------------+------------+------------+
        | bridge type)     | (6,0)-IPv6 | (6,1)-IPv6 | (6,2)-IPv6 | (6,3)-IPv6 | (6,4)-IPv6 | (6,5)-IPv6 |
        |                  |            |            |            |            |            |            |
        +------------------+------------+------------+------------+------------+------------+------------+

        The "filtered subhashrings" are essentially filtered copies of their
        respective subhashring, such that they only contain bridges which
        support IPv4 or IPv6, respectively.  (I have no idea of the relation
        between ``(6,0)-IPv4`` and ``(6,0)-IPv6``, including whether or not
        their contents are disjoint. I didn't design this shit, I'm just
        redesigning it.)

        Thus, in this example, we end up with **12 total subhashrings**.
        """
        logging.info("Prepopulating %s distributor hashrings..." % self.name)

        for filterFn in [filterBridgesByIP4, filterBridgesByIP6]:
            # XXX Distributors should have a "totalClusters" property in order
            # to avoid reusing this unclear construct all over the place.  (Or
            # just get rid of the idea of "categories".)
            for cluster in range(self.numberOfClusters + len(self.categories)):
                filters = self._buildHashringFilters([filterFn,], cluster)
                key1 = getHMAC(self.splitter.key, "Order-Bridges-In-Ring-%d" % cluster)
                ring = bridgedb.Bridges.BridgeRing(key1, self.answerParameters)
                # For consistency with previous implementation of this method,
                # only set the "name" for "clusters" which are in this
                # distributor's categories:
                if cluster >= self.numberOfClusters:
                    ring.setName('{0} Ring'.format(self.name))
                self.splitter.addRing(ring, filters,
                                      filterBridgesByRules(filters),
                                      populate_from=self.splitter.bridges)

    def insert(self, bridge):
        """Assign a bridge to this distributor."""
        self.splitter.insert(bridge)

    def _buildHashringFilters(self, previousFilters, clientCluster):
        totalRings = self.numberOfClusters + len(self.categories)
        g = filterAssignBridgesToRing(self.splitter.hmac, totalRings, clientCluster)
        previousFilters.append(g)
        return frozenset(previousFilters)

    def getBridges(self, bridgeRequest, interval, N=1):
        """Return a list of bridges to give to a user.

        :type bridgeRequest: :class:`bridgedb.https.request.HTTPSBridgeRequest`
        :param bridgeRequest: A :class:`~bridgedb.bridgerequest.BridgeRequestBase`
            with the :data:`~bridgedb.bridgerequest.BridgeRequestBase.client`
            attribute set to a string containing the client's IP address.
        :param str interval: The time period when we got this request.  This
            can be any string, so long as it changes with every period.
        :param int N: The number of bridges to try to give back. (default: 1)
        :rtype: list
        :return: A list of :class:`~bridgedb.Bridges.Bridge`s to include in
            the response. See
            :meth:`bridgedb.HTTPServer.WebResourceBridges.getBridgeRequestAnswer`
            for an example of how this is used.
        """
        logging.info("Attempting to return %d bridges to client %s..."
                     % (N, bridgeRequest.client))

        if not len(self.splitter):
            logging.warn("Bailing! Splitter has zero bridges!")
            return []

        # The cluster the client should draw bridges from:
        clientCluster = self.numberOfClusters
        # First, check if the client's IP is one of the known proxies in one
        # of our :data:`catagories`:
        for category in self.categories:
            if bridgeRequest.client in category:
                # The tag is a tag applied to a proxy IP address when it is
                # added to the bridgedb.proxy.ProxySet. For Tor Exit relays,
                # the default is 'exit_relay'. For other proxies loaded from
                # the PROXY_LIST_FILES config option, the default tag is the
                # full filename that the IP address originally came from.
                tag = category.getTag(bridgeRequest.client)
                logging.info("Client was from known proxy (tag: %s): %s" %
                             (tag, bridgeRequest.client))
                # Cluster Tor/proxy users into four groups.  This means that
                # no matter how many different Tor Exits or proxies a client
                # uses, the most they can ever get is four different sets of
                # bridge lines (per period).
                group = (int(ipaddr.IPAddress(bridgeRequest.client)) % 4) + 1
                area = "known-proxy-group-%d" % group
                break
            clientCluster += 1
        # If the client wasn't using Tor or any other known proxy, select the
        # client's cluster number based upon the /16 of the client's IP
        # address:
        else:
            # Areas (i.e. /16s) are grouped into the number of rings specified
            # by the N_IP_CLUSTERS configuration option.
            area = self.areaMapper(bridgeRequest.client)
            logging.debug("IP mapped to area:\t%s" % area)
            clientCluster = int(self.areaClusterHmac(area)[:8], 16) % self.numberOfClusters

        pos = self.areaOrderHmac("<%s>%s" % (interval, area))
        filters = self._buildHashringFilters(bridgeRequest.filters, clientCluster)

        logging.debug("Assigned client hashring position based on: <%s>%s" %
                      (interval, area))
        logging.debug("Bridges in splitter:\t%d" % len(self.splitter))
        logging.debug("Active bridge filters:\t%s" %
                      ' '.join([x.func_name for x in filters]))

        # Check wheth we have a cached copy of the hashring:
        if filters in self.splitter.filterRings.keys():
            logging.debug("Cache hit %s" % filters)
            _, ring = self.splitter.filterRings[filters]
        # Otherwise, construct a new hashring and populate it:
        else:
            logging.debug("Cache miss %s" % filters)
            key1 = getHMAC(self.splitter.key, "Order-Bridges-In-Ring-%d" % clientCluster)
            ring = bridgedb.Bridges.BridgeRing(key1, self.answerParameters)
            self.splitter.addRing(ring, filters, filterBridgesByRules(filters),
                                  populate_from=self.splitter.bridges)

        # Determine the appropriate number of bridges to give to the client:
        returnNum = getNumBridgesPerAnswer(ring, max_bridges_per_answer=N)
        answer = ring.getBridges(pos, returnNum)

        return answer

    def __len__(self):
        return len(self.splitter)

    def dumpAssignments(self, f, description=""):
        self.splitter.dumpAssignments(f, description)


class EmailBasedDistributor(Distributor):
    """Object that hands out bridges based on the email address of an incoming
    request and the current time period.

    :type splitter: :class:`~bridgedb.Bridges.BridgeRing`
    :ivar splitter: A hashring to hold all the bridges we hand out.
    """

    def __init__(self, key, domainmap, domainrules,
                 answerParameters=None, whitelist=None):
        """Create a bridge distributor which uses email.

        :type emailHmac: callable
        :param emailHmac: An hmac function used to order email addresses
            within a ring. See :func:`~bridgedb.crypto.getHMACFunc`.
        :param dict domainmap: A map from lowercase domains that we support
            mail from to their canonical forms. See `EMAIL_DOMAIN_MAP` option
            in `bridgedb.conf`.
        :param domainrules: DOCDOC
        :param answerParameters: DOCDOC
        :type whitelist: dict or ``None``
        :param whitelist: A dictionary that maps whitelisted email addresses
            to GnuPG fingerprints.
        """
        key1 = getHMAC(key, "Map-Addresses-To-Ring")
        self.emailHmac = getHMACFunc(key1, hex=False)

        key2 = getHMAC(key, "Order-Bridges-In-Ring")
        # XXXX clear the store when the period rolls over!
        self.domainmap = domainmap
        self.domainrules = domainrules
        self.whitelist = whitelist or dict()
        self.answerParameters = answerParameters

        #XXX cache options not implemented
        self.splitter = bridgedb.Bridges.FilteredBridgeSplitter(
            key2, max_cached_rings=5)

        self.setDistributorName('Email')

    def insert(self, bridge):
        """Assign a bridge to this distributor."""
        self.splitter.insert(bridge)

    def getBridges(self, bridgeRequest, interval, N=1):
        """Return a list of bridges to give to a user.

        :type bridgeRequest: :class:`~bridgedb.email.request.EmailBridgeRequest`
        :param bridgeRequest: A :class:`~bridgedb.bridgerequest.BridgeRequestBase`
            with the :data:`~bridgedb.bridgerequest.BridgeRequestBase.client`
            attribute set to a string containing the client's full, canonicalized
            email address.
        :param interval: The time period when we got this request. This can be
            any string, so long as it changes with every period.
        :param int N: The number of bridges to try to give back.
        """
        # All checks on the email address, such as checks for whitelisting and
        # canonicalization of domain name, are done in
        # :meth:`bridgedb.email.autoresponder.getMailTo` and
        # :meth:`bridgedb.email.autoresponder.SMTPAutoresponder.runChecks`.
        if (not bridgeRequest.client) or (bridgeRequest.client == 'default'):
            raise addr.BadEmail(
                ("%s distributor can't get bridges for invalid email email "
                 " address: %s") % (self.name, bridgeRequest.client))

        now = time.time()

        with bridgedb.Storage.getDB() as db:
            wasWarned = db.getWarnedEmail(bridgeRequest.client)
            lastSaw = db.getEmailTime(bridgeRequest.client)

            logging.info("Attempting to return for %d bridges for %s..."
                         % (N, bridgeRequest.client))

            if lastSaw is not None:
                if bridgeRequest.client in self.whitelist.keys():
                    logging.info(("Whitelisted email address %s was last seen "
                                  "%d seconds ago.")
                                 % (bridgeRequest.client, now - lastSaw))
                elif (lastSaw + MAX_EMAIL_RATE) >= now:
                    wait = (lastSaw + MAX_EMAIL_RATE) - now
                    logging.info("Client %s must wait another %d seconds."
                                 % (bridgeRequest.client, wait))
                    if wasWarned:
                        raise IgnoreEmail("Client was warned.",
                                          bridgeRequest.client)
                    else:
                        logging.info("Sending duplicate request warning.")
                        db.setWarnedEmail(bridgeRequest.client, True, now)
                        db.commit()
                        raise TooSoonEmail("Must wait %d seconds" % wait,
                                           bridgeRequest.client)

            # warning period is over
            elif wasWarned:
                db.setWarnedEmail(bridgeRequest.client, False)

            pos = self.emailHmac("<%s>%s" % (interval, bridgeRequest.client))

            ring = None
            ruleset = frozenset(bridgeRequest.filters)
            if ruleset in self.splitter.filterRings.keys():
                logging.debug("Cache hit %s" % ruleset)
                _, ring = self.splitter.filterRings[ruleset]
            else:
                # cache miss, add new ring
                logging.debug("Cache miss %s" % ruleset)

                # add new ring
                key1 = getHMAC(self.splitter.key, "Order-Bridges-In-Ring")
                ring = bridgedb.Bridges.BridgeRing(key1, self.answerParameters)
                self.splitter.addRing(ring, ruleset,
                                      filterBridgesByRules(ruleset),
                                      populate_from=self.splitter.bridges)

            numBridgesToReturn = getNumBridgesPerAnswer(ring,
                                                        max_bridges_per_answer=N)
            result = ring.getBridges(pos, numBridgesToReturn)

            db.setEmailTime(bridgeRequest.client, now)
            db.commit()

        return result

    def __len__(self):
        return len(self.splitter)

    def cleanDatabase(self):
        with bridgedb.Storage.getDB() as db:
            try:
                db.cleanEmailedBridges(time.time() - MAX_EMAIL_RATE)
                db.cleanWarnedEmails(time.time() - MAX_EMAIL_RATE)
            except:
                db.rollback()
                raise
            else:
                db.commit()

    def dumpAssignments(self, f, description=""):
        self.splitter.dumpAssignments(f, description)

    def prepopulateRings(self):
        # populate all rings (for dumping assignments and testing)
        for filterFn in [filterBridgesByIP4, filterBridgesByIP6]:
            ruleset = frozenset([filterFn])
            key1 = getHMAC(self.splitter.key, "Order-Bridges-In-Ring")
            ring = bridgedb.Bridges.BridgeRing(key1, self.answerParameters)
            self.splitter.addRing(ring, ruleset,
                                  filterBridgesByRules([filterFn]),
                                  populate_from=self.splitter.bridges)
