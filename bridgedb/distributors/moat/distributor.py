# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_moat_distributor -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Nick Mathewson
#           Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           Matthew Finkel 0x017DD169EA793BE2 <sysrqb@torproject.org>
# :copyright: (c) 2013-2017, Isis Lovecruft
#             (c) 2013-2017, Matthew Finkel
#             (c) 2007-2017, The Tor Project, Inc.
# :license: see LICENSE for licensing information

"""
bridgedb.distributors.moat.distributor
==========================

A Distributor that hands out bridges through a web interface.

.. inheritance-diagram:: MoatDistributor
    :parts: 1
"""

from bridgedb.distributors.https.distributor import HTTPSDistributor

class MoatDistributor(HTTPSDistributor):
    """A bridge distributor for Moat, a system which uses a JSON API to
    provide a remote application with data necessary to the creation of a
    user interface for distributing bridges.

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
        super(MoatDistributor, self).__init__(totalSubrings, key, proxies,
                                              answerParameters)
