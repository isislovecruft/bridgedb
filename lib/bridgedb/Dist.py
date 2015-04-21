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

import logging
import time

import bridgedb.Storage

from bridgedb.Bridges import BridgeRing
from bridgedb.Bridges import FilteredBridgeSplitter
from bridgedb.crypto import getHMAC
from bridgedb.crypto import getHMACFunc
from bridgedb.distribute import Distributor
from bridgedb.filters import byFilters
from bridgedb.filters import byIPv4
from bridgedb.filters import byIPv6
from bridgedb.filters import bySubring
from bridgedb.parse import addr


MAX_EMAIL_RATE = 3*3600

class IgnoreEmail(addr.BadEmail):
    """Raised when we get requests from this address after rate warning."""

class TooSoonEmail(addr.BadEmail):
    """Raised when we got a request from this address too recently."""

class EmailRequestedHelp(Exception):
    """Raised when a client has emailed requesting help."""

class EmailRequestedKey(Exception):
    """Raised when an incoming email requested a copy of our GnuPG keys."""


class EmailBasedDistributor(Distributor):
    """Object that hands out bridges based on the email address of an incoming
    request and the current time period.

    :type hashring: :class:`~bridgedb.Bridges.BridgeRing`
    :ivar hashring: A hashring to hold all the bridges we hand out.
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
        super(EmailBasedDistributor, self).__init__(key)

        key1 = getHMAC(key, "Map-Addresses-To-Ring")
        self.emailHmac = getHMACFunc(key1, hex=False)

        key2 = getHMAC(key, "Order-Bridges-In-Ring")
        # XXXX clear the store when the period rolls over!
        self.domainmap = domainmap
        self.domainrules = domainrules
        self.whitelist = whitelist or dict()
        self.answerParameters = answerParameters

        #XXX cache options not implemented
        self.hashring = FilteredBridgeSplitter(key2, max_cached_rings=5)
        self.name = "Email"

    def bridgesPerResponse(self, hashring=None):
        return super(EmailBasedDistributor, self).bridgesPerResponse(hashring)

    def insert(self, bridge):
        """Assign a bridge to this distributor."""
        self.hashring.insert(bridge)

    def getBridges(self, bridgeRequest, interval):
        """Return a list of bridges to give to a user.

        :type bridgeRequest: :class:`~bridgedb.email.request.EmailBridgeRequest`
        :param bridgeRequest: A :class:`~bridgedb.bridgerequest.BridgeRequestBase`
            with the :data:`~bridgedb.bridgerequest.BridgeRequestBase.client`
            attribute set to a string containing the client's full, canonicalized
            email address.
        :param interval: The time period when we got this request. This can be
            any string, so long as it changes with every period.
        """
        # All checks on the email address, such as checks for whitelisting and
        # canonicalization of domain name, are done in
        # :meth:`bridgedb.email.autoresponder.getMailTo` and
        # :meth:`bridgedb.email.autoresponder.SMTPAutoresponder.runChecks`.
        if (not bridgeRequest.client) or (bridgeRequest.client == 'default'):
            raise addr.BadEmail(
                ("%s distributor can't get bridges for invalid email email "
                 " address: %s") % (self.name, bridgeRequest.client))

        logging.info("Attempting to get bridges for %s..." % bridgeRequest.client)

        now = time.time()

        with bridgedb.Storage.getDB() as db:
            wasWarned = db.getWarnedEmail(bridgeRequest.client)
            lastSaw = db.getEmailTime(bridgeRequest.client)
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
            if ruleset in self.hashring.filterRings.keys():
                logging.debug("Cache hit %s" % ruleset)
                _, ring = self.hashring.filterRings[ruleset]
            else:
                # cache miss, add new ring
                logging.debug("Cache miss %s" % ruleset)

                # add new ring
                key1 = getHMAC(self.key, "Order-Bridges-In-Ring")
                ring = BridgeRing(key1, self.answerParameters)
                self.hashring.addRing(ring, ruleset, byFilters(ruleset),
                                      populate_from=self.hashring.bridges)

            returnNum = self.bridgesPerResponse(ring)
            result = ring.getBridges(pos, returnNum)

            db.setEmailTime(bridgeRequest.client, now)
            db.commit()

        return result

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

    def prepopulateRings(self):
        # populate all rings (for dumping assignments and testing)
        for filterFn in [byIPv4, byIPv6]:
            ruleset = frozenset([filterFn])
            key1 = getHMAC(self.key, "Order-Bridges-In-Ring")
            ring = BridgeRing(key1, self.answerParameters)
            self.hashring.addRing(ring, ruleset, byFilters([filterFn]),
                                  populate_from=self.hashring.bridges)
