# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_EmailServer -*-
# BridgeDB by Nick Mathewson.
# Copyright (c) 2007-2013, The Tor Project, Inc.
# See LICENSE for licensing information

"""This module implements the email interface to the bridge database."""

from __future__ import unicode_literals

from email import message
import gettext
import gpgme
import io
import logging
import re
import time

from ipaddr import IPv4Address
from ipaddr import IPv6Address

from twisted.internet import defer
from twisted.internet import reactor
from twisted.internet.task import LoopingCall
from twisted.mail import smtp

from zope.interface import implements

from bridgedb import Dist
from bridgedb import I18n
from bridgedb import safelog
from bridgedb import translations
from bridgedb.crypto import getGPGContext
from bridgedb.crypto import gpgSignMessage
from bridgedb.crypto import NEW_BUFFER_INTERFACE
from bridgedb.Filters import filterBridgesByIP6
from bridgedb.Filters import filterBridgesByIP4
from bridgedb.Filters import filterBridgesByTransport
from bridgedb.Filters import filterBridgesByNotBlockedIn
from bridgedb.parse import addr
from bridgedb.parse.addr import BadEmail
from bridgedb.parse.addr import UnsupportedDomain
from bridgedb.parse.addr import canonicalizeEmailDomain


def getBridgeDBEmailAddrFromList(ctx, address_list):
    """Loop through a list of (full name, email address) pairs and look up our
       mail address. If our address isn't found (which can't happen), return
       the default ctx from address so we can keep on working.
    """
    email = ctx.fromAddr
    for _, address in address_list:
        # Strip the @torproject.org part from the address
        idx = address.find('@')
        if idx != -1:
            username = address[:idx]
            # See if the user looks familiar. We do a 'find' instead
            # of compare because we might have a '+' address here
            if username.find(ctx.username) != -1:
                email = address
    return email

def getMailResponse(lines, ctx):
    """Given a list of lines from an incoming email message, and a
       MailContext object, parse the email and decide what to do in response.
       If we want to answer, return a 2-tuple containing the address that
       will receive the response, and a readable filelike object containing
       the response.  Return None,None if we shouldn't answer.
    """
    raw = io.StringIO()
    raw.writelines([unicode('{0}\n'.format(line)) for line in lines])
    raw.seek(0)

    msg = smtp.rfc822.Message(raw)
    # Extract data from the headers.
    msgID = msg.getheader("Message-ID", None)
    subject = msg.getheader("Subject", None) or "[no subject]"

    fromHeader = msg.getaddr("From")
    senderHeader = msg.getaddr("Sender")

    clientAddrHeader = None
    try:
        clientAddrHeader = fromHeader[1]
    except (IndexError, TypeError, AttributeError):
        pass

    if not clientAddrHeader:
        logging.warn("No From header on incoming mail.")
        try:
            clientAddrHeader = senderHeader[1]
        except (IndexError, TypeError, AttributeError):
            pass

    if not clientAddrHeader:
        logging.warn("No Sender header on incoming mail.")
        return None, None

    try:
        clientAddr = addr.normalizeEmail(clientAddrHeader,
                                         ctx.cfg.EMAIL_DOMAIN_MAP,
                                         ctx.cfg.EMAIL_DOMAIN_RULES)
    except (UnsupportedDomain, BadEmail) as error:
        logging.warn(error)
        return None, None

    # RFC822 requires at least one 'To' address
    clientToList = msg.getaddrlist("To")
    clientToAddr = getBridgeDBEmailAddrFromList(ctx, clientToList)

    # Look up the locale part in the 'To:' address, if there is one and get
    # the appropriate Translation object
    lang = translations.getLocaleFromPlusAddr(clientToAddr)
    t = translations.installTranslations(lang)

    canon = ctx.cfg.EMAIL_DOMAIN_MAP
    for domain, rule in ctx.cfg.EMAIL_DOMAIN_RULES.items():
        if domain not in canon.keys():
            canon[domain] = domain
    for domain in ctx.cfg.EMAIL_DOMAINS:
        canon[domain] = domain

    try:
        _, clientDomain = addr.extractEmailAddress(clientAddr.lower())
        canonical = canonicalizeEmailDomain(clientDomain, canon)
    except (UnsupportedDomain, BadEmail) as error:
        logging.warn(error)
        return None, None

    rules = ctx.cfg.EMAIL_DOMAIN_RULES.get(canonical, [])

    if 'dkim' in rules:
        # getheader() returns the last of a given kind of header; we want
        # to get the first, so we use getheaders() instead.
        dkimHeaders = msg.getheaders("X-DKIM-Authentication-Results")
        dkimHeader = "<no header>"
        if dkimHeaders:
            dkimHeader = dkimHeaders[0]
        if not dkimHeader.startswith("pass"):
            logging.info("Rejecting bad DKIM header on incoming email: %r "
                         % dkimHeader)
            return None, None

    # Was the magic string included
    #for ln in lines:
    #    if ln.strip().lower() in ("get bridges", "subject: get bridges"):
    #        break
    #else:
    #    logging.info("Got a mail from %r with no bridge request; dropping",
    #                 clientAddr)
    #    return None,None

    # Figure out which bridges to send
    unblocked = transport = ipv6 = skippedheaders = False
    bridgeFilterRules = []
    addressClass = None
    for ln in lines:
        # ignore all lines before the subject header
        if "subject" in ln.strip().lower():
            skippedheaders = True
        if not skippedheaders:
            continue

        if "ipv6" in ln.strip().lower():
            ipv6 = True
        if "transport" in ln.strip().lower():
            try:
                transport = re.search("transport ([_a-zA-Z][_a-zA-Z0-9]*)",
                        ln).group(1).strip()
            except (TypeError, AttributeError):
                transport = None
            logging.debug("Got request for transport: %s" % transport)
        if "unblocked" in ln.strip().lower():
            try:
                unblocked = re.search("unblocked ([a-zA-Z]{2,4})",
                        ln).group(1).strip()
            except (TypeError, AttributeError):
                transport = None

    if ipv6:
        bridgeFilterRules.append(filterBridgesByIP6)
        addressClass = IPv6Address
    else:
        bridgeFilterRules.append(filterBridgesByIP4)
        addressClass = IPv4Address

    if transport:
        bridgeFilterRules = [filterBridgesByTransport(transport, addressClass)]

    if unblocked:
        rules.append(filterBridgesByNotBlockedIn(unblocked,
                                                 addressClass,
                                                 transport))

    try:
        interval = ctx.schedule.getInterval(time.time())
        bridges = ctx.distributor.getBridgesForEmail(clientAddr,
            interval, ctx.N,
            countryCode=None,
            bridgeFilterRules=bridgeFilterRules)

    # Handle rate limited email
    except Dist.TooSoonEmail as err:
        logging.info("Got a mail too frequently; warning '%s': %s."
                     % (clientAddr, err))
        # MAX_EMAIL_RATE is in seconds, convert to hours
        body = buildSpamWarningTemplate(t) % (Dist.MAX_EMAIL_RATE / 3600)
        return composeEmail(ctx.fromAddr, clientAddr, subject, body, msgID,
                            gpgContext=ctx.gpgContext)
    except Dist.IgnoreEmail as err:
        logging.info("Got a mail too frequently; ignoring '%s': %s."
                     % (clientAddr, err))
        return None, None
    except BadEmail as err:
        logging.info("Got a mail from a bad email address '%s': %s."
                     % (clientAddr, err))
        return None, None

    answer = "(no bridges currently available)\n"
    if bridges:
        with_fp = ctx.cfg.EMAIL_INCLUDE_FINGERPRINTS
        answer = "".join("  %s\n" % b.getConfigLine(
            includeFingerprint=with_fp,
            addressClass=addressClass,
            transport=transport,
            request=clientAddr) for b in bridges)

    body = buildMessageTemplate(t) % answer
    # Generate the message.
    return composeEmail(ctx.fromAddr, clientAddr, subject, body, msgID,
                        gpgContext=ctx.gpgContext)

def buildMessageTemplate(t):
    msg_template = t.gettext(I18n.BRIDGEDB_TEXT[0]) + "\n\n" \
                   + t.gettext(I18n.BRIDGEDB_TEXT[1]) + "\n\n" \
                   + "%s\n" \
                   + t.gettext(I18n.BRIDGEDB_TEXT[2]) + "\n\n" \
                   + t.gettext(I18n.BRIDGEDB_TEXT[3]) + "\n\n" \
                   + t.gettext(I18n.BRIDGEDB_TEXT[4]) + "\n\n" \
                   + t.gettext(I18n.BRIDGEDB_TEXT[5])+ "\n\n"
    # list supported commands, e.g. ipv6, transport
    msg_template = msg_template \
                   + "  " + t.gettext(I18n.BRIDGEDB_TEXT[6])+ "\n" \
                   + "  " + t.gettext(I18n.BRIDGEDB_TEXT[7])+ "\n\n"
    return msg_template

def buildSpamWarningTemplate(t):
    msg_template = t.gettext(I18n.BRIDGEDB_TEXT[0]) + "\n\n" \
                   + t.gettext(I18n.BRIDGEDB_TEXT[8] % "%s") + "\n\n"
    return msg_template

def _ebReplyToMailFailure(fail):
    """Errback for a :api:`twisted.mail.smtp.SMTPSenderFactory`.

    :param fail: A :api:`twisted.python.failure.Failure` which occurred during
        the transaction.
    """
    logging.debug("EmailServer._ebReplyToMailFailure() called with %r" % fail)
    error = fail.getErrorMessage() or "unknown failure."
    logging.exception("replyToMail Failure: %s" % error)
    return None

def replyToMail(lines, ctx):
    """Reply to an incoming email. Maybe.

    If no `response` is returned from :func:`getMailResponse`, then the
    incoming email will not be responded to at all. This can happen for
    several reasons, for example: if the DKIM signature was invalid or
    missing, or if the incoming email came from an unacceptable domain, or if
    there have been too many emails from this client in the allotted time
    period.

    :param list lines: A list of lines from an incoming email message.
    :type ctx: :class:`MailContext`
    :param ctx: The configured context for the email server.
    :rtype: :api:`twisted.internet.defer.Deferred`
    :returns: A ``Deferred`` which will callback when the response has been
        successfully sent, or errback if an error occurred while sending the
        email.
    """
    logging.info("Got an email; deciding whether to reply.")
    sendToUser, response = getMailResponse(lines, ctx)

    d = defer.Deferred()

    if response is None:
        logging.debug("We don't feel like talking to %s." % sendToUser)
        return d

    response.seek(0)
    logging.info("Sending reply to %s" % sendToUser)
    factory = smtp.SMTPSenderFactory(ctx.smtpFromAddr, sendToUser,
                                     response, d, retries=0, timeout=30)
    d.addErrback(_ebReplyToMailFailure)
    reactor.connectTCP(ctx.smtpServer, ctx.smtpPort, factory)
    return d

def composeEmail(fromAddr, clientAddr, subject, body,
                 msgID=None, gpgContext=None):

    if not subject.startswith("Re:"):
        subject = "Re: %s" % subject

    msg = smtp.rfc822.Message(io.StringIO())
    msg.setdefault("From", fromAddr)
    msg.setdefault("To", clientAddr)
    msg.setdefault("Message-ID", smtp.messageid())
    msg.setdefault("Subject", subject)
    if msgID:
        msg.setdefault("In-Reply-To", msgID)
    msg.setdefault("Date", smtp.rfc822date())
    msg.setdefault('Content-Type', 'text/plain; charset="utf-8"')
    headers = [': '.join(m) for m in msg.items()]

    if NEW_BUFFER_INTERFACE:
        mail = io.BytesIO()
        buff = buffer
    else:
        mail = io.StringIO()
        buff = unicode

    mail.writelines(buff("\r\n".join(headers)))
    mail.writelines(buff("\r\n"))
    mail.writelines(buff("\r\n"))

    if not gpgContext:
        mail.write(buff(body))
    else:
        signature, siglist = gpgSignMessage(gpgContext, body)
        if signature:
            mail.writelines(buff(signature))
    mail.seek(0)

    # Only log the email text (including all headers) if SAFE_LOGGING is
    # disabled:
    if not safelog.safe_logging:
        logging.debug("Email contents:\n\n%s" % mail.read())
        mail.seek(0)
    else:
        logging.debug("Email text for %r created." % clientAddr)

    return clientAddr, mail


class MailContext(object):
    """Helper object that holds information used by email subsystem."""

    def __init__(self, cfg, dist, sched):
        # Reject any RCPT TO lines that aren't to this user.
        self.username = (cfg.EMAIL_USERNAME or "bridges")
        # Reject any mail longer than this.
        self.maximumSize = 32*1024
        # Use this server for outgoing mail.
        self.smtpServer = (cfg.EMAIL_SMTP_HOST or "127.0.0.1")
        self.smtpPort = (cfg.EMAIL_SMTP_PORT or 25)
        # Use this address in the MAIL FROM line for outgoing mail.
        self.smtpFromAddr = (cfg.EMAIL_SMTP_FROM_ADDR or
                             "bridges@torproject.org")
        # Use this address in the "From:" header for outgoing mail.
        self.fromAddr = (cfg.EMAIL_FROM_ADDR or
                         "bridges@torproject.org")
        # An EmailBasedDistributor object
        self.distributor = dist
        # An IntervalSchedule object
        self.schedule = sched
        # The number of bridges to send for each email.
        self.N = cfg.EMAIL_N_BRIDGES_PER_ANSWER

        # Initialize a gpg context or set to None for backward compatibliity.
        self.gpgContext = getGPGContext(cfg)

        self.cfg = cfg

class MailMessage(object):
    """Plugs into the Twisted Mail and receives an incoming message."""
    implements(smtp.IMessage)

    def __init__(self, ctx):
        """Create a new MailMessage from a MailContext."""
        self.ctx = ctx
        self.lines = []
        self.nBytes = 0
        self.ignoring = False

    def lineReceived(self, line):
        """Called when we get another line of an incoming message."""
        self.nBytes += len(line)
        if not safelog.safe_logging:
            logging.debug("> %s", line.rstrip("\r\n"))
        if self.nBytes > self.ctx.maximumSize:
            self.ignoring = True
        else:
            self.lines.append(line)

    def eomReceived(self):
        """Called when we receive the end of a message."""
        if not self.ignoring:
            replyToMail(self.lines, self.ctx)
        return defer.succeed(None)

    def connectionLost(self):
        """Called if we die partway through reading a message."""
        pass

class MailDelivery(object):
    """Plugs into Twisted Mail and handles SMTP commands."""
    implements(smtp.IMessageDelivery)

    def setBridgeDBContext(self, ctx):
        self.ctx = ctx

    def receivedHeader(self, helo, origin, recipients):
        """Create the ``Received:`` header for an incoming email.

        :type helo: tuple
        :param helo: The lines received during SMTP client HELO.
        :type origin: :api:`twisted.mail.smtp.Address`
        :param origin: The email address of the sender.
        :type recipients: list
        :param recipients: A list of :api:`twisted.mail.smtp.User` instances.
        """
        cameFrom = "%s (%s [%s])" % (helo[0] or origin, helo[0], helo[1])
        cameFor = ', '.join(["<{0}>".format(recp.dest) for recp in recipients])
        hdr = str("Received: from %s for %s; %s" % (cameFrom, cameFor,
                                                    smtp.rfc822date()))
        return hdr

    def validateFrom(self, helo, origin):
        return origin

    def validateTo(self, user):
        """If the local user that was addressed isn't our configured local user
        or doesn't contain a '+' with a prefix matching the local configured
        user: Yell.
        """
        u = user.dest.local
        # Hasplus? If yes, strip '+foo'
        idx = u.find('+')
        if idx != -1:
            u = u[:idx]
        if u != self.ctx.username:
            raise smtp.SMTPBadRcpt(user)
        return lambda: MailMessage(self.ctx)

class MailFactory(smtp.SMTPFactory):
    """Plugs into Twisted Mail; creates a new MailDelivery whenever we get
       a connection on the SMTP port."""

    def __init__(self, *a, **kw):
        smtp.SMTPFactory.__init__(self, *a, **kw)
        self.delivery = MailDelivery()

    def setBridgeDBContext(self, ctx):
        self.ctx = ctx
        self.delivery.setBridgeDBContext(ctx)

    def buildProtocol(self, addr):
        p = smtp.SMTPFactory.buildProtocol(self, addr)
        p.delivery = self.delivery
        return p

def addSMTPServer(cfg, dist, sched):
    """Set up a smtp server.
         cfg -- a configuration object from Main.  We use these options:
                EMAIL_BIND_IP
                EMAIL_PORT
                EMAIL_N_BRIDGES_PER_ANSWER
                EMAIL_DOMAIN_RULES
         dist -- an EmailBasedDistributor object.
         sched -- an IntervalSchedule object.
    """
    ctx = MailContext(cfg, dist, sched)
    factory = MailFactory()
    factory.setBridgeDBContext(ctx)
    ip = cfg.EMAIL_BIND_IP or ""
    reactor.listenTCP(cfg.EMAIL_PORT, factory, interface=ip)
    # Set up a LoopingCall to run every 30 minutes and forget old email times.
    lc = LoopingCall(dist.cleanDatabase)
    lc.start(1800, now=False)
    return factory
