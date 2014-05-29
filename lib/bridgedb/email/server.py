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


def checkDKIM(message, rules):
    """Check the DKIM verification results header.

    This check is only run if the incoming email, **message**, originated from
    a domain for which we're configured (in the ``EMAIL_DOMAIN_RULES``
    dictionary in the config file) to check DKIM verification results for.

    :type message: :api:`twisted.mail.smtp.rfc822.Message`
    :param message: The incoming client request email, including headers.
    :param dict rules: The list of configured ``EMAIL_DOMAIN_RULES`` for the
        canonical domain which the client's email request originated from.

    :rtype: bool
    :returns: ``False`` if:
        1. We're supposed to expect and check the DKIM headers for the
           client's email provider domain.
        2. Those headers were *not* okay.
        Otherwise, returns ``True``.
    """
    logging.info("Checking DKIM verification results...")
    logging.debug("Domain has rules: %s" % ', '.join(rules))

    if 'dkim' in rules:
        # getheader() returns the last of a given kind of header; we want
        # to get the first, so we use getheaders() instead.
        dkimHeaders = message.getheaders("X-DKIM-Authentication-Results")
        dkimHeader = "<no header>"
        if dkimHeaders:
            dkimHeader = dkimHeaders[0]
        if not dkimHeader.startswith("pass"):
            logging.info("Rejecting bad DKIM header on incoming email: %r "
                         % dkimHeader)
            return False
    return True

def createResponseBody(lines, context, client, lang='en'):
    """Parse the **lines** from an incoming email request and determine how to
    respond.

    :param list lines: The list of lines from the original request sent by the
        client.
    :type context: class:`MailContext`
    :param context: The context which contains settings for the email server.
    :type client: :api:`twisted.mail.smtp.Address`
    :param client: The client's email address which should be in the
        :header:`To:` header of the response email.
    :param str lang: The 2-5 character locale code to use for translating the
        email. This is obtained from a client sending a email to a valid plus
        address which includes the translation desired, i.e. by sending an
        email to ``bridges+fa@torproject.org``, the client should receive a
        response in Farsi.
    :rtype: None or str
    :returns: None if we shouldn't respond to the client (i.e., if they have
        already received a rate-limiting warning email). Otherwise, returns a
        string containing the (optionally translated) body for the email
        response which we should send out.
    """
    t = translations.installTranslations(lang)
    bridges = None
    try:
        bridgeRequest = request.determineBridgeRequestOptions(lines)

        # The request was invalid, respond with a help email which explains
        # valid email commands:
        if not bridgeRequest.isValid():
            raise EmailRequestedHelp("Email request from '%s' was invalid."
                                     % str(client))

        # Otherwise they must have requested bridges:
        interval = context.schedule.getInterval(time.time())
        bridges = context.distributor.getBridgesForEmail(
            str(client),
            interval,
            context.nBridges,
            countryCode=None,
            bridgeFilterRules=bridgeRequest.filters)
    except EmailRequestedHelp as error:
        logging.info(error)
        return templates.buildWelcomeText(t, client)
    except EmailRequestedKey as error:
        logging.info(error)
        return templates.buildKeyMessage(t, client)
    except TooSoonEmail as error:
        logging.info("Got a mail too frequently: %s." % error)
        return templates.buildSpamWarning(t, client)
    except (IgnoreEmail, BadEmail) as error:
        logging.info(error)
        # Don't generate a response if their email address is unparsable or
        # invalid, or if we've already warned them about rate-limiting:
        return None
    else:
        answer = "(no bridges currently available)\r\n"
        if bridges:
            transport = bridgeRequest.justOnePTType()
            answer = "".join("  %s\r\n" % b.getConfigLine(
                includeFingerprint=context.includeFingerprints,
                addressClass=bridgeRequest.addressClass,
                transport=transport,
                request=str(client)) for b in bridges)
        return templates.buildAnswerMessage(t, client, answer)

def generateResponse(fromAddress, clientAddress, body, subject=None,
                     messageID=None, gpgContext=None):
    """Create a :class:`MailResponse`, which acts like an in-memory
    ``io.StringIO`` file, by creating and writing all headers and the email
    body into the file-like ``MailResponse.mailfile``.

    :param str fromAddress: The rfc:`2821` email address which should be in
        the :header:`From:` header.
    :param str clientAddress: The rfc:`2821` email address which should be in
        the :header:`To:` header.
    :param str subject: The string to write to the :header:`subject` header.
    :param str body: The body of the email. If a **gpgContext** is also given,
        and that ``Context`` has email signing configured, then
        :meth:`MailResponse.writeBody` will generate and include any
        ascii-armored OpenPGP signatures in the **body**.
    :type messageID: None or str
    :param messageID: The :rfc:`2822` specifier for the :header:`Message-ID:`
        header, if including one is desirable.
    :type gpgContext: None or ``gpgme.Context``.
    :param gpgContext: A pre-configured GPGME context. See
        :meth:`~crypto.getGPGContext`.
    :rtype: :class:`MailResponse`
    :returns: A ``MailResponse`` which contains the entire email. To obtain
        the contents of the email, including all headers, simply use
        :meth:`MailResponse.readContents`.
    """
    response = MailResponse(gpgContext)
    response.writeHeaders(fromAddress, clientAddress, subject,
                          inReplyTo=messageID)
    response.writeBody(body)

    # Only log the email text (including all headers) if SAFE_LOGGING is
    # disabled:
    if not safelog.safe_logging:
        contents = response.readContents()
        logging.debug("Email contents:\n%s" % contents)
    else:
        logging.debug("Email text for %r created." % clientAddress)
    response.rewind()
    return response


class MailContext(object):
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
        self.hostaddr = socket.gethostbyname(self.hostname)
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

        .. note:: Be sure that ``MailContext.domainRules`` and
            ``MailContext.domainMap`` are set appropriately before calling
            this method.

        This method is automatically called during initialisation, and the
        resulting domain map is stored as ``MailContext.canon``.

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


class MailResponse(object):
    """Holds information for generating a response email for a request.

    .. todo:: At some point, we may want to change this class to optionally
        handle creating Multipart MIME encoding messages, so that we can
        include attachments. (This would be useful for attaching our GnuPG
        keyfile, for example, rather than simply pasting it into the body of
        the email.)

    :type _buff: unicode or buffer
    :cvar _buff: Used internally to write lines for the response email into
        the ``_mailfile``. The reason why both of these attributes have two
        possible types is for the same Python-buggy reasons which require
        :data:`~bridgedb.crypto.NEW_BUFFER_INTERFACE`.
    :type mailfile: :class:`io.StringIO` or :class:`io.BytesIO`.
    :cvar mailfile: An in-memory file for storing the formatted headers and
        body of the response email.
    """
    _buff = buffer if NEW_BUFFER_INTERFACE else unicode
    mailfile = io.BytesIO if NEW_BUFFER_INTERFACE else io.StringIO

    def __init__(self, gpgContext=None):
        """Create a response to an email we have recieved.

        This class deals with correctly formatting text for the response email
        headers and the response body into an instance of :cvar:`mailfile`.

        :type gpgContext: None or ``gpgme.Context``
        :param gpgContext: A pre-configured GPGME context. See
            :meth:`bridgedb.crypto.getGPGContext` for obtaining a
            pre-configured **gpgContext**. If given, and the ``Context`` has
            been configured to sign emails, then a response email body string
            given to :meth:`writeBody` will be signed before being written
            into the ``mailfile``.
        """
        self.gpgContext = gpgContext
        self.mailfile = self.mailfile()
        self.closed = False

    # These are methods and attributes for controlling I/O operations on our
    # underlying ``mailfile``.

    def close(self):
        self.mailfile.close()
        self.closed = True
    close.__doc__ = mailfile.close.__doc__

    # The following are custom methods to control reading and writing to the
    # underlying ``mailfile``.

    def readContents(self):
        """Read the all the contents written thus far to the :cvar:`mailfile`,
        and then :meth:`seek` to return to the original pointer position we
        were at before this method was called.

        :rtype: str
        :returns: The entire contents of the :cvar:`mailfile`.
        """
        pointer = self.mailfile.tell()
        self.mailfile.seek(0)
        contents = self.mailfile.read()
        self.mailfile.seek(pointer)
        return contents

    def rewind(self):
        """Rewind to the very beginning of the :cvar:`mailfile`."""
        self.mailfile.seek(0)

    def write(self, line):
        """Any **line** written to me will have ``'\r\n'`` appended to it."""
        if line.find('\n') != -1:
            # If **line** contains newlines, send it to :meth:`writelines` to
            # break it up so that we can replace them with '\r\n':
            self.writelines(line)
        else:
            self.mailfile.write(self._buff(line + '\r\n'))
            self.mailfile.flush()

    def writelines(self, lines):
        """Calls :meth:`write` for each line in **lines**."""
        if isinstance(lines, basestring):
            for ln in lines.split('\n'):
                self.write(ln)
        elif isinstance(lines, (list, tuple,)):
            for ln in lines:
                self.write(ln)

    def writeHeaders(self, fromAddress, toAddress, subject=None,
                     inReplyTo=None, includeMessageID=True,
                     contentType='text/plain; charset="utf-8"', **kwargs):
        """Write all headers into the response email.

        :param str fromAddress: The email address for the ``From:`` header.
        :param str toAddress: The email address for the ``To:`` header.
        :type subject: None or str
        :param subject: The ``Subject:`` header.
        :type inReplyTo: None or str
        :param inReplyTo: If set, an ``In-Reply-To:`` header will be
            generated. This should be set to the ``Message-ID:`` header from
            the client's original request email.
        :param bool includeMessageID: If ``True``, generate and include a
            ``Message-ID:`` header for the response.
        :param str contentType: The ``Content-Type:`` header.
        :kwargs: If given, the key will become the name of the header, and the
            value will become the Contents of that header.
        """
        self.write("From: %s" % fromAddress)
        self.write("To: %s" % toAddress)
        if includeMessageID:
            self.write("Message-ID: %s" % smtp.messageid())
        if inReplyTo:
            self.write("In-Reply-To: %s" % inReplyTo)
        self.write("Content-Type: %s" % contentType)
        self.write("Date: %s" % smtp.rfc822date())

        if not subject:
            subject = '[no subject]'
        if not subject.lower().startswith('re'):
            subject = "Re: " + subject
        self.write("Subject: %s" % subject)

        if kwargs:
            for headerName, headerValue in kwargs.items():
                headerName = headerName.capitalize()
                headerName = headerName.replace(' ', '-')
                headerName = headerName.replace('_', '-')
                self.write("%s: %s" % (headerName, headerValue))

        # The first blank line designates that the headers have ended:
        self.write("\r\n")

    def writeBody(self, body):
        """Write the response body into the :cvar:`mailfile`.

        If ``MailResponse.gpgContext`` is set, and signing is configured, the
        **body** will be automatically signed before writing its contents into
        the ``mailfile``.

        :param str body: The body of the response email.
        """
        if self.gpgContext:
            body, _ = gpgSignMessage(self.gpgContext, body)
        self.writelines(body)


class MailMessage(object):
    """Plugs into the Twisted Mail and receives an incoming message.

    :ivar list lines: A list of lines from an incoming email message.
    :ivar int nBytes: The number of bytes received thus far.
    :ivar bool ignoring: If ``True``, we're ignoring the rest of this message
        because it exceeded :ivar:`MailContext.maximumSize`.
    """
    implements(smtp.IMessage)

    def __init__(self, context, fromCanonical=None):
        """Create a new MailMessage from a MailContext.

        :type context: :class:`MailContext`
        :param context: The configured context for the email server.
        :type canonicalFrom: str or None
        :param canonicalFrom: The canonical domain which this message was
            received from. For example, if ``'gmail.com'`` is the configured
            canonical domain for ``'googlemail.com'`` and a message is
            received from the latter domain, then this would be set to the
            former.
        """
        self.context = context
        self.fromCanonical = fromCanonical
        self.lines = []
        self.nBytes = 0
        self.ignoring = False

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
        """Called when we receive the end of a message."""
        if not self.ignoring:
            self.reply()
        return defer.succeed(None)

    def connectionLost(self):
        """Called if we die partway through reading a message."""
        pass

    def getIncomingMessage(self):
        """Create and parse an :rfc:`2822` message object for all ``lines``
        received thus far.

        :rtype: :api:`twisted.mail.smtp.rfc822.Message`
        :returns: A ``Message`` comprised of all lines received thus far.
        """
        rawMessage = io.StringIO()
        for ln in self.lines:
            rawMessage.writelines(unicode(ln) + unicode('\n'))
        rawMessage.seek(0)
        return smtp.rfc822.Message(rawMessage)

    def getClientAddress(self, incoming):
        """Attempt to get the client's email address from an incoming email.

        :type incoming: :api:`twisted.mail.smtp.rfc822.Message`
        :param incoming: An incoming ``Message``, i.e. as returned from
            :meth:`getIncomingMessage`.
        :rtype: ``None`` or :api:`twisted.mail.smtp.Address`
        :returns: The client's email ``Address``, if it originated from a
            domain that we accept and the address was well-formed. Otherwise,
            returns ``None``.
        """
        addrHeader = None
        try: fromAddr = incoming.getaddr("From")[1]
        except (IndexError, TypeError, AttributeError): pass
        else: addrHeader = fromAddr

        if not addrHeader:
            logging.warn("No From header on incoming mail.")
            try: senderHeader = incoming.getaddr("Sender")[1]
            except (IndexError, TypeError, AttributeError): pass
            else: addrHeader = senderHeader
        if not addrHeader:
            logging.warn("No Sender header on incoming mail.")
        else:
            try:
                client = smtp.Address(addr.normalizeEmail(
                    addrHeader,
                    self.context.domainMap,
                    self.context.domainRules))
            except (UnsupportedDomain, BadEmail, smtp.AddressError) as error:
                logging.warn(error)
            else:
                return client

    def getMailFrom(self, incoming):
        """Find our address in the recipients list of the **incoming** message.

        :type incoming: :api:`twisted.mail.smtp.rfc822.Message`
        :param incoming: An incoming ``Message``, i.e. as returned from
            :meth:`getIncomingMessage`.
        :rtype: str
        :return: Our address from the recipients list. If we can't find it
            return our default ``SMTP_FROM_ADDRESS`` from the config file.
        """
        logging.debug("Searching for our email address in 'To:' header...")

        ours = None

        try:
            ourAddress = smtp.Address(self.context.fromAddr)
            allRecipients = incoming.getaddrlist("To")

            for _, addr in allRecipients:
                recipient = smtp.Address(addr)
                if not (ourAddress.domain in recipient.domain):
                    logging.debug(("Not our domain (%s) or subdomain, skipping"
                                   " email address: %s")
                                  % (ourAddress.domain, str(recipient)))
                    continue
                # The recipient's username should at least start with ours,
                # but it still might be a '+' address.
                if not recipient.local.startswith(ourAddress.local):
                    logging.debug(("Username doesn't begin with ours, skipping"
                                   " email address: %s") % str(recipient))
                    continue
                # Ignore everything after the first '+', if there is one.
                beforePlus = recipient.local.split('+', 1)[0]
                if beforePlus == ourAddress.local:
                    ours = str(recipient)
            if not ours:
                raise BadEmail(allRecipients)

        except Exception as error:
            logging.error(("Couldn't find our email address in incoming email "
                           "headers: %r" % error))
            # Just return the email address that we're configured to use:
            ours = self.context.fromAddr

        logging.debug("Found our email address: %s." % ours)
        return ours

    def getCanonicalDomain(self, domain):
        try:
            canonical = canonicalizeEmailDomain(domain, self.context.canon)
        except (UnsupportedDomain, BadEmail) as error:
            logging.warn(error)
        else:
            return canonical

    def reply(self):
        """Reply to an incoming email. Maybe.

        If nothing is returned from either :func:`createResponseBody` or
        :func:`generateResponse`, then the incoming email will not be
        responded to at all. This can happen for several reasons, for example:
        if the DKIM signature was invalid or missing, or if the incoming email
        came from an unacceptable domain, or if there have been too many
        emails from this client in the allotted time period.

        :rtype: :api:`twisted.internet.defer.Deferred`
        :returns: A ``Deferred`` which will callback when the response has
            been successfully sent, or errback if an error occurred while
            sending the email.
        """
        logging.info("Got an email; deciding whether to reply.")

        def _replyEB(fail):  # pragma: no cover
            """Errback for a :api:`twisted.mail.smtp.SMTPSenderFactory`.

            :param fail: A :api:`twisted.python.failure.Failure` which occurred during
            the transaction.
            """
            logging.debug("_replyToMailEB() called with %r" % fail)
            error = fail.getTraceback() or "Unknown"
            logging.error(error)

        d = defer.Deferred()
        d.addErrback(_replyEB)

        incoming = self.getIncomingMessage()
        recipient = self.getMailFrom(incoming)
        client = self.getClientAddress(incoming)

        if not client:
            return d

        if not self.fromCanonical:
            self.fromCanonical = self.getCanonicalDomain(client.domain)
        rules = self.context.domainRules.get(self.fromCanonical, [])
        if not checkDKIM(incoming, rules):
            return d

        clientAddr = '@'.join([client.local, client.domain])
        messageID = incoming.getheader("Message-ID", None)
        subject = incoming.getheader("Subject", None)

        # Look up the locale part in the 'To:' address, if there is one and
        # get the appropriate Translation object:
        lang = translations.getLocaleFromPlusAddr(recipient)
        logging.info("Client requested email translation: %s" % lang)

        body = createResponseBody(self.lines, self.context, client, lang)
        if not body: return d  # The client was already warned.

        response = generateResponse(self.context.fromAddr, clientAddr, body,
                                    subject, messageID, self.context.gpgContext)
        if not response: return d

        logging.info("Sending reply to %s" % client)
        factory = smtp.SMTPSenderFactory(self.context.smtpFromAddr, clientAddr,
                                         response, d, retries=0, timeout=30)
        reactor.connectTCP(self.context.smtpServerIP,
                           self.context.smtpServerPort,
                           factory)
        return d


class MailDelivery(object):
    """Plugs into Twisted Mail and handles SMTP commands."""
    implements(smtp.IMessageDelivery)

    def setBridgeDBContext(self, context):
        self.context = context
        self.fromCanonical = None

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
        hdr = str("Received: from %s for %s; %s"
                  % (cameFrom, cameFor, smtp.rfc822date()))
        return hdr

    def validateFrom(self, helo, origin):
        """Validate the ``MAIL FROM:`` address on the incoming SMTP connection.

        This is done at the SMTP layer. Meaning that if a Postfix or other
        email server is proxying emails from the outside world to BridgeDB,
        the :api:`origin.domain <twisted.email.smtp.Address.domain` will be
        set to the local hostname. Therefore, if the SMTP ``MAIL FROM:``
        domain name is our own hostname (as returned from
        :func:`socket.gethostname`) or our own FQDN, allow the connection.

        Otherwise, if the ``MAIL FROM:`` domain has a canonical domain in our
        mapping (taken from :ivar:`context.canon <MailContext.canon>`, which
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
                (origin.domain == self.context.hostaddr)):
                return origin
            else:
                logging.debug("ORIGIN DOMAIN: %r" % origin.domain)
                canonical = canonicalizeEmailDomain(origin.domain,
                                                    self.context.canon)
                logging.debug("Got canonical domain: %r" % canonical)
                self.fromCanonical = canonical
        except UnsupportedDomain as error:
            logging.info(error)
            raise smtp.SMTPBadSender(origin.domain)
        except Exception as error:
            logging.exception(error)
        return origin  # This method *cannot* return None, or it'll cause a 503.

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

        return lambda: MailMessage(self.context, self.fromCanonical)


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
