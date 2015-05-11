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

"""A :class:`~bridgedb.distribute.Distributor` which hands out
:class:`bridges <bridgedb.bridges.Bridge>` to clients via an email interface.
"""

import logging
import math
import time

import bridgedb.Storage

from bridgedb import strings
from bridgedb.crypto import getHMAC
from bridgedb.crypto import getHMACFunc
from bridgedb.distribute import Distributor
from bridgedb.filters import byIPv4
from bridgedb.filters import byIPv6
from bridgedb.filters import byTransport
from bridgedb.hashring import ConstrainedHashring
from bridgedb.hashring import ConsistentHashring
from bridgedb.hashring import ProportionalHashring
from bridgedb.parse import addr
from bridgedb.parse.addr import extractEmailAddress


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

    The bridges which are distributed to a client by this :class:`Distributor`
    are deterministically computed via relation to the interval in which the
    client's request occurred, as well as the client's email provider (one of
    :property:`supportedDomains`) and the client's normalised email address.

    :type hashring: :class:`~bridgedb.hashring.ProportionalHashring`
    :ivar hashring: A hashring to hold all the bridges we hand out.
    """

    #: The minimum amount of time (in seconds) which must pass before a client
    #: who has previously been given an email response must wait before being
    #: eligible to receive another response.
    emailRateMax = MAX_EMAIL_RATE

    def __init__(self, key, domainmap, domainrules, constraints=None,
                 proportions=None, whitelist=None, schedule=None):
        """Create a bridge distributor which uses email.

        .. todo:: Make :class:`schedules <bridgedb.schedule.ScheduledInterval>`
            be attributes of :class:`~bridgedb.distribute.Distributor`s, rather
            than part of :class:`~bridgedb.email.server.MailServerContext` and
            :class:`~bridgedb.https.server.BridgeResource`.

        :param dict domainmap: A map from lowercase domains which we support
            mail from to their canonical forms. See `EMAIL_DOMAIN_MAP` option
            in `bridgedb.conf`.
        :param domainrules: DOCDOC
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

        :type proportions: dict or ``None``
        :param proportions: A map of supported domains to the proportions
            which their respective hashring should receive, relative to the
            other domains.  For example, if the :class:`EmailDistributor` has
            20 bridges total to distribute to clients, and if the
            **proportions** were::

                {'example.com': 2,
                 'fubar.com': 9,}

            then approximately 4 and 16 bridges would be given to
            ``example.com`` and ``fubar.com`` respectively.  If not given,
            then all supported domains will receive equal amounts of bridges.

        :type whitelist: dict or ``None``
        :param whitelist: A dictionary that maps whitelisted email addresses
            to GnuPG fingerprints.
        """
        super(EmailDistributor, self).__init__(key)
        self._proportions = dict()
        self._domainToSubring = dict()

        self.whitelist = whitelist or dict()
        self.domainmap = domainmap
        self.domainrules = domainrules
        self.constraints = constraints
        self.proportions = proportions

        #: The hashring cacheSize is relative to the number of supported
        #: domains, because there is a separate subring for each domain.
        self._cacheSize = int(math.e * len(self.supportedDomains))
        self.hashring = ProportionalHashring(getHMAC(self.key, "Hashring"))
        self.hashring.name = "Email"

        self.buildHashrings()
        self.name = "Email"

    @property
    def proportions(self):
        """Get the proportions of allocated bridges per supported domain.

        :rtype: dict
        :returns: A map of supported domains to the proportions which their
            respective hashring should receive, relative to the other domains.
            For example, if the :class:`EmailDistributor` has 20 bridges total
            to distribute to clients, and if the **proportions** were::

                {'example.com': 2,
                 'fubar.com': 9,}

            then approximately 4 and 16 bridges would be given to
            ``example.com`` and ``fubar.com`` respectively.  If not given,
            then all supported domains will receive equal amounts of bridges.
        """
        return self._proportions

    @proportions.setter
    def proportions(self, proportions):
        """Set the proportions of allocated bridges per supported domain."""

        domains = self.supportedDomains

        if not proportions:
            numberDomains = len(domains)
            # Account for the whitelist by making it its own special allocation
            if self.whitelist:
                numberDomains += 1
            proportions = dict(zip(domains, [1 for _ in range(numberDomains)]))
            logging.info(("All supported email domains will receive equal "
                          "amounts of bridges."))
        else:
            # Check that every supported email domain has been assigned a
            # proportion, i.e. that there are no domains which are only in one
            # set or the other:
            if set(proportions).symmetric_difference(domains):
                raise ValueError(
                    ("Email domain proportions mentions domains %r, but the "
                     "currently supported domains are: %r\n"
                     "In proportions but not in supported domains: %s\n"
                     "In supported domains but not in proportions: %s") %
                    (proportions, domains, proportions.difference(domains),
                     set(domains).difference(proportions)))
            if self.whitelist and not "whitelist" in proportions:
                proportions["whitelist"] = 1

        self._proportions = proportions

    @property
    def supportedDomains(self):
        """Get a list of all unique, canonical domains which incoming emails
        are currently permitted from.

        :rtype: list
        """
        domains = list(set(self.domainmap.values()))
        if self.whitelist:
            domains.append("whitelist")
        return domains

    def bridgesPerResponse(self, hashring=None):
        return super(EmailDistributor, self).bridgesPerResponse(hashring)

    def buildHashrings(self):
        if self.hashring.subrings:
            logging.debug(("But the Email Distributor's hashrings were already"
                           "built!"))
            return

        for domain in self.supportedDomains:
            logging.info("Constructing separate hashring for supported email "
                         "domain: %s" % domain)
            proportion = self.proportions[domain]
            subkey = getHMAC(self.key, "Bridges-Assigned-To-%s" % domain)
            subring = ConstrainedHashring(subkey, cacheSize=self._cacheSize)
            self.hashring.addSubring(subring, domain, proportion=proportion)
            self._domainToSubring[domain] = subring

        logging.info(self.hashring.tree())

    def determineResponse(self, address, now):
        """Determine how we should respond to an email from **emailaddress**
        received just **now**.

        .. warn:: This method interacts with BridgeDB's databases, and, as
            such, it is *not* thread-safe.

        If an email from **emailaddress** was recently received, and the
        **emailaddress** isn't contained within the :data:`whitelist`, then
        this method checks whether the client has already waited out the
        rate-limiting period, :data:`emailRateMax`.  If the client hasn't
        waited long enough, then :

          1. The client has been warned. :exc:`IgnoreEmail` will be raised
             (i.e. nothing will be sent to the client and their email will be
             dropped on the floor).

          2. The client hasn't been warned yet (for this rate-limit period).
             :exc:`TooSoonEmail` will be raised, in order to send out a
             rate-limit warning to the client.

        :param str address: The email address to decide how to respond to.
        :param int now: A timestamp for when this email was received, in
            seconds since the UNIX Epoch.
        :raises TooSoonEmail: if a email explaining rate limiting should be
            sent to **emailaddress**.
        :raises IgnoreEmail: if the email should be ignored (e.g. because
            **emailaddress** was already warned).
        """
        with bridgedb.Storage.getDB() as db:
            warned = db.getWarnedEmail(address)
            lastseen = db.getEmailTime(address)

        if lastseen is not None:
            expiry = lastseen + self.emailRateMax
            if address in self.whitelist:
                logging.info("Whitelisted address %s last seen %d seconds ago."
                             % (address, now - lastseen))
            elif expiry >= now:
                wait = expiry - now
                logging.info("Client %s must wait another %d seconds."
                              % (address, wait))
                if warned:
                    raise IgnoreEmail("Client %s was already warned."
                                      % address, address)
                else:
                    with bridgedb.Storage.getDB() as db:
                        db.setWarnedEmail(address, True, now)
                        db.commit()

                    logging.info("Sending email rate-limit warning.")
                    raise TooSoonEmail("Must wait %d seconds" % wait, address)
        elif warned:
            logging.debug(("Removing stale DB entry for last warning email "
                           "sent to %s...") % address)
            with bridgedb.Storage.getDB() as db:
                db.setWarnedEmail(address, False, now)
                db.commit()

    def findSubringFor(self, client):
        """Get the appropriate subring for a **client**, based on their email
        provider's domain name.

        :rtype: :class:`~bridgedb.hashring.ConstrainedHashring`
        """
        localpart, domain = extractEmailAddress(client)
        domain = "whitelist" if client in self.whitelist else domain
        logging.debug("Getting appropriate subring for client from %s" % domain)
        return self._domainToSubring.get(domain)

    def getBridges(self, bridgeRequest, interval, clock=None):
        """Return a list of bridges to give to a user.

        .. hint:: All checks on the email address (which should be stored in
            the ``bridgeRequest.client`` attribute), such as checks for
            whitelisting and canonicalization of domain name, are done in
            :meth:`bridgedb.email.autoresponder.getMailTo` and
            :meth:`bridgedb.email.autoresponder.SMTPAutoresponder.runChecks`.

        .. warn:: This method interacts with BridgeDB's databases, and, as
            such, it is *not* thread-safe.

        :type bridgeRequest:
            :class:`~bridgedb.email.request.EmailBridgeRequest`
        :param bridgeRequest: A
            :class:`~bridgedb.bridgerequest.BridgeRequestBase` with the
            :data:`~bridgedb.bridgerequest.BridgeRequestBase.client` attribute
            set to a string containing the client's full, canonicalized email
            address.
        :param interval: The time period when we got this request. This can be
            any string, so long as it changes with every period.
        :type clock: :api:`twisted.internet.task.Clock`
        :param clock: If given, use the clock to ask what time it is, rather
            than :api:`time.time`. This should likely only be used for
            testing.
        :raises BadEmail: If the ``bridgeRequest.client`` appears not to have
            been set to the client's email address.
        :raises TooSoonEmail: if a email explaining rate limiting should be
            sent to **emailaddress**.
        :raises IgnoreEmail: if the email should be ignored (e.g. because
            **emailaddress** was already warned).
        :rtype: list or ``None``
        :returns: A list of :class:`~bridgedb.bridges.Bridges` for the
            ``bridgeRequest.client``, if allowed.  Otherwise, returns ``None``.
        """
        if not bridgeRequest.client or bridgeRequest.client == 'default':
            raise addr.BadEmail(
                "%s distributor can't get bridges for invalid email address: %s"
                % (self.name, bridgeRequest.client), bridgeRequest.client)

        logging.info("Attempting to get bridges for %s..." % bridgeRequest.client)

        if clock:
            now = clock.seconds()
        else:
            now = time.time()

        try:
            self.determineResponse(bridgeRequest.client, now)
        except (IgnoreEmail, TooSoonEmail):
            raise

        subring = self.findSubringFor(bridgeRequest.client)
        position = self.getHashringPosition(interval, bridgeRequest.client)
        filters = bridgeRequest.filters

        logging.debug("Client request within time interval: %s" % interval)
        logging.debug("Bridge filters: %s" % ", ".join([f.name for f in filters]))
        logging.debug("Assigned client to sub-hashring: %s" % subring.name)
        logging.debug("Assigned client to sub-hashring position: %s" % position.encode('hex'))
        logging.debug("Total bridges in sub-hashring: %d" % len(subring))

        filtered = subring.reduce(*filters)
        result = subring.retrieve(position, self.bridgesPerResponse(subring))

        logging.debug("Total filtered bridges: %d" % len(filtered))

        with bridgedb.Storage.getDB() as db:
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

    def regenerateCaches(self):
        """Regenerate this distributor's hashring and sub-hashring caches with
        any new bridges which should belong in them.
        """
        logging.info("Regenerating caches for %s distributor hashrings..." % self.name)

        filters = [byIPv4, byIPv6]
        defaultTransport = strings._getDefaultTransport()
        if defaultTransport:
            filters.append(byTransport(defaultTransport))

        for subring in self.hashring.subrings:
            for filtre in filters:
                subring.addToCache(filtre)
