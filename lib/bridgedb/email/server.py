# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_email_server -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Nick Mathewson <nickm@torproject.org>
#           Isis Lovecruft <isis@torproject.org> 0xA3ADB67A2CDB8B35
#           Matthew Finkel <sysrqb@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2014, The Tor Project, Inc.
#             (c) 2013-2014, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________


"""Servers which interface with clients and distribute bridges over SMTP."""

from __future__ import unicode_literals

import logging
import io
import socket
import time

from twisted.internet import defer
from twisted.internet import reactor
from twisted.internet.task import LoopingCall
from twisted.mail import smtp

from zope.interface import implements

from bridgedb import safelog
from bridgedb import translations
from bridgedb.crypto import getGPGContext
from bridgedb.crypto import gpgSignMessage
from bridgedb.crypto import NEW_BUFFER_INTERFACE
from bridgedb.Dist import EmailRequestedHelp
from bridgedb.Dist import EmailRequestedKey
from bridgedb.Dist import TooSoonEmail
from bridgedb.Dist import IgnoreEmail
from bridgedb.email import templates
from bridgedb.email import request
from bridgedb.parse import addr
from bridgedb.parse.addr import BadEmail
from bridgedb.parse.addr import UnsupportedDomain
from bridgedb.parse.addr import canonicalizeEmailDomain


class MailServerContext(object):
    """Helper object that holds information used by email subsystem.

    :ivar str username: Reject any RCPT TO lines that aren't to this
        user. See the ``EMAIL_USERNAME`` option in the config file.
        (default: ``'bridges'``)
    :ivar int maximumSize: Reject any incoming emails longer than
        this size (in bytes). (default: 3084 bytes).
    :ivar int smtpPort: The port to use for outgoing SMTP.
    :ivar str smtpServer: The IP address to use for outgoing SMTP.
    :ivar str smtpFromAddr: Use this address in the raw SMTP ``MAIL FROM``
        line for outgoing mail. (default: ``bridges@torproject.org``)
    :ivar str fromAddr: Use this address in the email :header:`From:`
        line for outgoing mail. (default: ``bridges@torproject.org``)
    :ivar int nBridges: The number of bridges to send for each email.
    :ivar gpgContext: A ``gpgme.GpgmeContext`` (as created by
        :func:`bridgedb.crypto.getGPGContext`), or None if we couldn't create
        a proper GPGME context for some reason.
    """

    def __init__(self, config, distributor, schedule):
        """Create a context for storing configs for email bridge distribution.

        :type config: :class:`bridgedb.persistent.Conf`
        :type distributor: :class:`bridgedb.Dist.EmailBasedDistributor`.
        :param distributor: The distributor will handle getting the correct
            bridges (or none) for a client for us.
        :type schedule: :class:`bridgedb.schedule.ScheduledInterval`.
        :param schedule: An interval-based scheduler, used to help the
            :ivar:`distributor` know if we should give bridges to a client.
        """
        self.config = config
        self.distributor = distributor
        self.schedule = schedule

        self.maximumSize = smtp.SMTP.MAX_LENGTH
        self.includeFingerprints = config.EMAIL_INCLUDE_FINGERPRINTS
        self.nBridges = config.EMAIL_N_BRIDGES_PER_ANSWER

        self.username = (config.EMAIL_USERNAME or "bridges")
        self.hostname = socket.gethostname()
        self.fromAddr = (config.EMAIL_FROM_ADDR or "bridges@torproject.org")
        self.smtpFromAddr = (config.EMAIL_SMTP_FROM_ADDR or self.fromAddr)
        self.smtpServerPort = (config.EMAIL_SMTP_PORT or 25)
        self.smtpServerIP = (config.EMAIL_SMTP_HOST or "127.0.0.1")

        self.domainRules = config.EMAIL_DOMAIN_RULES or {}
        self.domainMap = config.EMAIL_DOMAIN_MAP or {}
        self.canon = self.buildCanonicalDomainMap()

        self.gpgContext = getGPGContext(config)

    def buildCanonicalDomainMap(self):
        """Build a map for all email provider domains from which we will accept
        emails to their canonical domain name.

        .. note:: Be sure that ``MailServerContext.domainRules`` and
            ``MailServerContext.domainMap`` are set appropriately before calling
            this method.

        This method is automatically called during initialisation, and the
        resulting domain map is stored as ``MailServerContext.canon``.

        :rtype: dict
        :returns: A dictionary which maps all domains and subdomains which we
            accept emails from to their second-level, canonical domain names.
        """
        canon = self.domainMap
        for domain, rule in self.domainRules.items():
            if domain not in canon.keys():
                canon[domain] = domain
        for domain in self.config.EMAIL_DOMAINS:
            canon[domain] = domain
        return canon


class SMTPMessage(object):
    """Plugs into the Twisted Mail and receives an incoming message.

    :ivar list lines: A list of lines from an incoming email message.
    :ivar int nBytes: The number of bytes received thus far.
    :ivar bool ignoring: If ``True``, we're ignoring the rest of this message
        because it exceeded :ivar:`MailServerContext.maximumSize`.
    :ivar canonicalFromSMTP: See :meth:`SMTPAutoresponder.runChecks`.
    :ivar canonicalFromEmail: See :meth:`SMTPAutoresponder.runChecks`.
    :ivar canonicalDomainRules: See :meth:`SMTPAutoresponder.runChecks`.
    :type message: :api:`twisted.mail.smtp.rfc822.Message` or ``None``
    :ivar message: The incoming email message.
    :type responder: :class:`autoresponder.SMTPAutoresponder`
    :ivar responder: A parser and checker for the incoming :ivar:`message`. If
        it decides to do so, it will build a
        :meth:`~autoresponder.SMTPAutoresponder.reply` email and
        :meth:`~autoresponder.SMTPAutoresponder.send` it.
    """
    implements(smtp.IMessage)

    def __init__(self, context, canonicalFromSMTP=None):
        """Create a new SMTPMessage.

        These are created automatically via
        :class:`SMTPIncomingDelivery`.

        :param context: The configured :class:`MailServerContext`.
        :type canonicalFromSMTP: str or None
        :param canonicalFromSMTP: The canonical domain which this message was
            received from. For example, if ``'gmail.com'`` is the configured
            canonical domain for ``'googlemail.com'`` and a message is
            received from the latter domain, then this would be set to the
            former.
        """
        self.context = context
        self.canon = context.canon
        self.canonicalFromSMTP = canonicalFromSMTP
        self.canonicalFromEmail = None
        self.canonicalDomainRules = None

        self.lines = []
        self.nBytes = 0
        self.ignoring = False

        self.message = None
        self.responder = autoresponder.SMTPAutoresponder()
        self.responder.incoming = self

    def lineReceived(self, line):
        """Called when we get another line of an incoming message."""
        self.nBytes += len(line)
        if self.nBytes > self.context.maximumSize:
            self.ignoring = True
        else:
            self.lines.append(line)
        if not safelog.safe_logging:
            logging.debug("> %s", line.rstrip("\r\n"))

    def eomReceived(self):
        """Tell the :ivar:`responder` to reply when we receive an EOM."""
        if not self.ignoring:
            self.message = self.getIncomingMessage()
            self.responder.reply()
        return defer.succeed(None)

    def connectionLost(self):
        """Called if we die partway through reading a message."""
        pass

    def getIncomingMessage(self):
        """Create and parse an :rfc:`2822` message object for all :ivar:`lines`
        received thus far.

        :rtype: :api:`twisted.mail.smtp.rfc822.Message`
        :returns: A ``Message`` comprised of all lines received thus far.
        """
        rawMessage = io.StringIO()
        for line in self.lines:
            rawMessage.writelines(unicode(line) + unicode('\n'))
        rawMessage.seek(0)
        return smtp.rfc822.Message(rawMessage)


class SMTPIncomingDelivery(smtp.SMTP):
    """Plugs into :class:`SMTPIncomingServerFactory` and handles SMTP commands
    for incoming connections.

    :type context: :class:`MailServerContext`
    :ivar context: A context containing SMTP/Email configuration settings.
    :ivar deferred: A :api:`deferred <twisted.internet.defer.Deferred>` which
        will be returned when :meth:`reply` is called. Additional callbacks
        may be set on this deferred in order to schedule additional actions
        when the response is being sent.
    :type fromCanonicalSMTP: str or ``None``
    :ivar fromCanonicalSMTP: If set, this is the canonicalized domain name of
       the address we received from incoming connection's ``MAIL FROM:``.
    """
    implements(smtp.IMessageDelivery)

    context = None
    deferred = defer.Deferred()
    fromCanonicalSMTP = None

    @classmethod
    def setContext(cls, context):
        """Set our :ivar:`context` to a new :class:`MailServerContext."""
        cls.context = context

    def receivedHeader(self, helo, origin, recipients):
        """Create the ``Received:`` header for an incoming email.

        :type helo: tuple
        :param helo: The lines received during SMTP client HELO.
        :type origin: :api:`twisted.mail.smtp.Address`
        :param origin: The email address of the sender.
        :type recipients: list
        :param recipients: A list of :api:`twisted.mail.smtp.User` instances.
        """
        helo_ = ' helo={0}'.format(helo[0]) if helo[0] else ''
        from_ = 'from %s ([%s]%s)' % (helo[0], helo[1], helo_)
        by_ = 'by %s with BridgeDB (%s)' % (smtp.DNSNAME, __version__)
        for_ = 'for %s; %s ' % (' '.join(map(str, recipients)), rfc822date())
        return str('Received: %s\n\t%s\n\t%s' % (from_, by_, for_))

    def validateFrom(self, helo, origin):
        """Validate the ``MAIL FROM:`` address on the incoming SMTP connection.

        This is done at the SMTP layer. Meaning that if a Postfix or other
        email server is proxying emails from the outside world to BridgeDB,
        the :api:`origin.domain <twisted.email.smtp.Address.domain` will be
        set to the local hostname. Therefore, if the SMTP ``MAIL FROM:``
        domain name is our own hostname (as returned from
        :func:`socket.gethostname`) or our own FQDN, allow the connection.

        Otherwise, if the ``MAIL FROM:`` domain has a canonical domain in our
        mapping (taken from :ivar:`context.canon <MailServerContext.canon>`, which
        is taken in turn from the ``EMAIL_DOMAIN_MAP``), then our
        :ivar:`fromCanonicalSMTP` is set to that domain.

        :type helo: tuple
        :param helo: The lines received during SMTP client HELO.
        :type origin: :api:`twisted.mail.smtp.Address`
        :param origin: The email address we received this message from.
        :raises: :api:`twisted.mail.smtp.SMTPBadSender` if the
            ``origin.domain`` was neither our local hostname, nor one of the
            canonical domains listed in :ivar:`context.canon`.
        :rtype: :api:`twisted.mail.smtp.Address`
        :returns: The ``origin``. We *must* return some non-``None`` data from
            this method, or else Twisted will reply to the sender with a 503
            error.
        """
        try:
            if ((origin.domain == self.context.hostname) or
                (origin.domain == smtp.DNSNAME)):
                self.fromCanonicalSMTP = origin.domain
            else:
                logging.debug("Canonicalizing client SMTP domain...")
                canonical = canonicalizeEmailDomain(origin.domain,
                                                    self.context.canon)
                logging.debug("Canonical SMTP domain: %r" % canonical)
                self.fromCanonicalSMTP = canonical
        except UnsupportedDomain as error:
            logging.info(error)
            raise smtp.SMTPBadSender(origin.domain)
        except Exception as error:
            logging.exception(error)

        # This method **cannot** return None, or it'll cause a 503 error.
        return origin

    def validateTo(self, user):
        """Validate the SMTP ``RCPT TO:`` address for the incoming connection.

        The local username and domain name to which this SMTP message is
        addressed, after being stripped of any ``'+'`` aliases, **must** be
        identical to those in the email address set our
        ``EMAIL_SMTP_FROM_ADDR`` configuration file option.

        :type user: :api:`twisted.mail.smtp.User`
        :param user: Information about the user this SMTP message was
            addressed to.
        :raises: A :api:`twisted.mail.smtp.SMTPBadRcpt` if any of the above
            conditions weren't met.
        :rtype: callable
        :returns: A parameterless function which returns an instance of
            :class:`SMTPMessage`.
        """
        logging.debug("Validating SMTP 'RCPT TO:' email address...")

        recipient = user.dest
        ourAddress = smtp.Address(self.context.smtpFromAddr)

        if not (ourAddress.domain in recipient.domain):
            logging.debug(("Not our domain (%s) or subdomain, skipping"
                           " SMTP 'RCPT TO' address: %s")
                          % (ourAddress.domain, str(recipient)))
            raise smtp.SMTPBadRcpt(str(recipient))
        # The recipient's username should at least start with ours,
        # but it still might be a '+' address.
        if not recipient.local.startswith(ourAddress.local):
            logging.debug(("Username doesn't begin with ours, skipping"
                           " SMTP 'RCPT TO' address: %s") % str(recipient))
            raise smtp.SMTPBadRcpt(str(recipient))
        # Ignore everything after the first '+', if there is one.
        beforePlus = recipient.local.split('+', 1)[0]
        if beforePlus != ourAddress.local:
            raise smtp.SMTPBadRcpt(str(recipient))

        return lambda: SMTPMessage(self.context, self.fromCanonicalSMTP)


class MailFactory(smtp.SMTPFactory):
    """Plugs into Twisted Mail; creates a new MailDelivery whenever we get
       a connection on the SMTP port."""

    def __init__(self, context=None, **kw):
        smtp.SMTPFactory.__init__(self, **kw)
        self.delivery = MailDelivery()
        if context:
            self.setBridgeDBContext(context)

    def setBridgeDBContext(self, context):
        self.context = context
        self.delivery.setBridgeDBContext(context)

    def buildProtocol(self, addr):
        p = smtp.SMTPFactory.buildProtocol(self, addr)
        p.delivery = self.delivery
        return p


def addServer(config, distributor, schedule):
    """Set up a SMTP server for responding to requests for bridges.

    :type config: :class:`bridgedb.persistent.Conf`
    :param config: A configuration object.
    :type distributor: :class:`bridgedb.Dist.EmailBasedDistributor`
    :param dist: A distributor which will handle database interactions, and
        will decide which bridges to give to who and when.
    :type schedule: :class:`bridgedb.schedule.ScheduledInterval`
    :param schedule: The schedule. XXX: Is this even used?
    """
    context = MailContext(config, distributor, schedule)
    factory = MailFactory(context)

    addr = config.EMAIL_BIND_IP or ""
    port = config.EMAIL_PORT

    reactor.listenTCP(port, factory, interface=addr)

    # Set up a LoopingCall to run every 30 minutes and forget old email times.
    lc = LoopingCall(distributor.cleanDatabase)
    lc.start(1800, now=False)

    return factory
