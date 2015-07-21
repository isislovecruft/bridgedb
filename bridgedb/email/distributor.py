# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_email_distributor -*-
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
.. py:module:: bridgedb.email.distributor
    :synopsis: A Distributor which hands out Bridges via an email interface.

bridgedb.email.autoresponder
============================

A :class:`~bridgedb.distribute.Distributor` which hands out :class:`bridges
<bridgedb.bridges.Bridge>` to clients via an email interface.

.. inheritance-diagram:: IgnoreEmail TooSoonEmail EmailRequestedHelp EmailRequestedKey EmailDistributor
    :parts: 1
"""

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


#: The minimum amount of time (in seconds) which must pass before a client who
#: has previously been given an email response must wait before being eligible
#: to receive another response.
MAX_EMAIL_RATE = 3 * 3600


class IgnoreEmail(addr.BadEmail):
    """Raised when we get requests from this address after rate warning."""


class TooSoonEmail(addr.BadEmail):
    """Raised when we got a request from this address too recently."""


class EmailRequestedHelp(Exception):
    """Raised when a client has emailed requesting help."""


class EmailRequestedKey(Exception):
    """Raised when an incoming email requested a copy of our GnuPG keys."""


class EmailDistributor(Distributor):
    """Object that hands out bridges based on the email address of an incoming
    request and the current time period.

    :type hashring: :class:`~bridgedb.Bridges.BridgeRing`
    :ivar hashring: A hashring to hold all the bridges we hand out.
    """

    #: The minimum amount of time (in seconds) which must pass before a client
    #: who has previously been given an email response must wait before being
    #: eligible to receive another response.
    emailRateMax = MAX_EMAIL_RATE

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
        super(EmailDistributor, self).__init__(key)

        self.domainmap = domainmap
        self.domainrules = domainrules
        self.whitelist = whitelist or dict()
        self.answerParameters = answerParameters

        key1 = getHMAC(key, "Map-Addresses-To-Ring")
        key2 = getHMAC(key, "Order-Bridges-In-Ring")

        self.emailHmac = getHMACFunc(key1, hex=False)
        #XXX cache options not implemented
        self.hashring = FilteredBridgeSplitter(key2, max_cached_rings=5)

        self.name = "Email"

    def bridgesPerResponse(self, hashring=None):
        return super(EmailDistributor, self).bridgesPerResponse(hashring)

    def getBridges(self, bridgeRequest, interval, clock=None):
        """Return a list of bridges to give to a user.

        .. hint:: All checks on the email address (which should be stored in
            the ``bridgeRequest.client`` attribute), such as checks for
            whitelisting and canonicalization of domain name, are done in
            :meth:`bridgedb.email.autoresponder.getMailTo` and
            :meth:`bridgedb.email.autoresponder.SMTPAutoresponder.runChecks`.

        :type bridgeRequest:
            :class:`~bridgedb.email.request.EmailBridgeRequest`
        :param bridgeRequest: A
            :class:`~bridgedb.bridgerequest.BridgeRequestBase` with the
            :data:`~bridgedb.bridgerequest.BridgeRequestBase.client` attribute
            set to a string containing the client's full, canonicalized email
            address.
        :type interval: str
        :param interval: The time period when we got this request. This can be
            any string, so long as it changes with every period.
        :type clock: :api:`twisted.internet.task.Clock`
        :param clock: If given, use the clock to ask what time it is, rather
            than :api:`time.time`. This should likely only be used for
            testing.
        :rtype: :any:`list` or ``None``
        :returns: A list of :class:`~bridgedb.bridges.Bridges` for the
            ``bridgeRequest.client``, if allowed.  Otherwise, returns ``None``.
        """
        if (not bridgeRequest.client) or (bridgeRequest.client == 'default'):
            raise addr.BadEmail(
                ("%s distributor can't get bridges for invalid email address: "
                 "%s") % (self.name, bridgeRequest.client), bridgeRequest.client)

        logging.info("Attempting to get bridges for %s..." % bridgeRequest.client)

        now = time.time()

        if clock:
            now = clock.seconds()

        with bridgedb.Storage.getDB() as db:
            wasWarned = db.getWarnedEmail(bridgeRequest.client)
            lastSaw = db.getEmailTime(bridgeRequest.client)
            if lastSaw is not None:
                if bridgeRequest.client in self.whitelist:
                    logging.info(
                        "Whitelisted address %s was last seen %d seconds ago."
                        % (bridgeRequest.client, now - lastSaw))
                elif (lastSaw + self.emailRateMax) >= now:
                    wait = (lastSaw + self.emailRateMax) - now
                    logging.info("Client %s must wait another %d seconds."
                                 % (bridgeRequest.client, wait))
                    if wasWarned:
                        raise IgnoreEmail(
                            "Client %s was warned." % bridgeRequest.client,
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
            filtres = frozenset(bridgeRequest.filters)
            if filtres in self.hashring.filterRings:
                logging.debug("Cache hit %s" % filtres)
                _, ring = self.hashring.filterRings[filtres]
            else:
                logging.debug("Cache miss %s" % filtres)
                key = getHMAC(self.key, "Order-Bridges-In-Ring")
                ring = BridgeRing(key, self.answerParameters)
                self.hashring.addRing(ring, filtres, byFilters(filtres),
                                      populate_from=self.hashring.bridges)

            returnNum = self.bridgesPerResponse(ring)
            result = ring.getBridges(pos, returnNum)

            db.setEmailTime(bridgeRequest.client, now)
            db.commit()

        return result

    def cleanDatabase(self):
        """Clear all emailed response and warning times from the database."""
        logging.info(("Cleaning all response and warning times for the %s "
                      "distributor from the database...") % self.name)
        with bridgedb.Storage.getDB() as db:
            try:
                db.cleanEmailedBridges(time.time() - self.emailRateMax)
                db.cleanWarnedEmails(time.time() - self.emailRateMax)
            except:
                db.rollback()
                raise
            else:
                db.commit()

    def prepopulateRings(self):
        """Prepopulate this distributor's hashrings and subhashrings with
        bridges.
        """
        logging.info("Prepopulating %s distributor hashrings..." % self.name)

        for filterFn in [byIPv4, byIPv6]:
            ruleset = frozenset([filterFn])
            key = getHMAC(self.key, "Order-Bridges-In-Ring")
            ring = BridgeRing(key, self.answerParameters)
            self.hashring.addRing(ring, ruleset, byFilters([filterFn]),
                                  populate_from=self.hashring.bridges)

        # Since prepopulateRings is called every half hour when the bridge
        # descriptors are re-parsed, we should clean the database then.
        self.cleanDatabase()
