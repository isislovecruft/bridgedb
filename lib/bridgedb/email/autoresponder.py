# -*- coding: utf-8; test-case-name: bridgedb.test.test_email_autoresponder -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Nick Mathewson <nickm@torproject.org>
#           Isis Lovecruft <isis@torproject.org> 0xA3ADB67A2CDB8B35
#           Matthew Finkel <sysrqb@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2015, The Tor Project, Inc.
#             (c) 2013-2015, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""
.. py:module:: bridgedb.email.autoresponder
    :synopsis: Functionality for autoresponding to incoming emails.

bridgedb.email.autoresponder
============================

Functionality for autoresponding to incoming emails.

::

  bridgedb.email.autoresponder
   | |_ createResponseBody - Parse lines from an incoming email and determine
   | |                       how to respond.
   | |_ generateResponse - Create an email response.
   |
   |_ EmailResponse - Holds information for generating a response to a request.
   |_ SMTPAutoresponder - An SMTP autoresponder for incoming mail.
..
"""

from __future__ import unicode_literals
from __future__ import print_function

import io
import logging
import time

from twisted.internet import defer
from twisted.internet import reactor
from twisted.mail import smtp
from twisted.python import failure

from bridgedb import safelog
from bridgedb.crypto import NEW_BUFFER_INTERFACE
from bridgedb.Dist import EmailRequestedHelp
from bridgedb.Dist import EmailRequestedKey
from bridgedb.Dist import TooSoonEmail
from bridgedb.Dist import IgnoreEmail
from bridgedb.email import dkim
from bridgedb.email import request
from bridgedb.email import templates
from bridgedb.parse import addr
from bridgedb.parse.addr import canonicalizeEmailDomain
from bridgedb.util import levenshteinDistance
from bridgedb import translations


def createResponseBody(lines, context, client, lang='en'):
    """Parse the **lines** from an incoming email request and determine how to
    respond.

    :param list lines: The list of lines from the original request sent by the
        client.
    :type context: class:`bridgedb.email.server.MailServerContext`
    :param context: The context which contains settings for the email server.
    :type client: :api:`twisted.mail.smtp.Address`
    :param client: The client's email address which should be in the
        ``'To:'`` header of the response email.
    :param str lang: The 2-5 character locale code to use for translating the
        email. This is obtained from a client sending a email to a valid plus
        address which includes the translation desired, i.e. by sending an
        email to `bridges+fa@torproject.org
        <mailto:bridges+fa@torproject.org>`__, the client should receive a
        response in Farsi.
    :rtype: None or str
    :returns: None if we shouldn't respond to the client (i.e., if they have
        already received a rate-limiting warning email). Otherwise, returns a
        string containing the (optionally translated) body for the email
        response which we should send out.
    """
    translator = translations.installTranslations(lang)
    bridges = None
    try:
        bridgeRequest = request.determineBridgeRequestOptions(lines)

        # The request was invalid, respond with a help email which explains
        # valid email commands:
        if not bridgeRequest.isValid():
            raise EmailRequestedHelp("Email request from '%s' was invalid."
                                     % str(client))

        # Otherwise they must have requested bridges:
        interval = context.schedule.intervalStart(time.time())
        bridges = context.distributor.getBridgesForEmail(
            str(client),
            interval,
            context.nBridges,
            countryCode=None,
            bridgeFilterRules=bridgeRequest.filters)
    except EmailRequestedHelp as error:
        logging.info(error)
        return templates.buildWelcomeText(translator, client)
    except EmailRequestedKey as error:
        logging.info(error)
        return templates.buildKeyMessage(translator, client)
    except TooSoonEmail as error:
        logging.info("Got a mail too frequently: %s." % error)
        return templates.buildSpamWarning(translator, client)
    except (IgnoreEmail, addr.BadEmail) as error:
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
        return templates.buildAnswerMessage(translator, client, answer)

def generateResponse(fromAddress, client, body, subject=None,
                     messageID=None, gpgSignFunc=None):
    """Create a :class:`EmailResponse`, which acts like an in-memory
    ``io.StringIO`` file, by creating and writing all headers and the email
    body into the file-like ``EmailResponse.mailfile``.

    :param str fromAddress: The rfc:`2821` email address which should be in
        the :header:`From:` header.
    :type client: :api:`twisted.mail.smtp.Address`
    :param client: The client's email address which should be in the
        ``'To:'`` header of the response email.
    :param str subject: The string to write to the ``Subject:'`` header.
    :param str body: The body of the email. If a **gpgSignFunc** is also
        given, then :meth:`EmailResponse.writeBody` will generate and include
        an ascii-armored OpenPGP signature in the **body**.
    :type messageID: None or str
    :param messageID: The :rfc:`2822` specifier for the ``'Message-ID:'``
        header, if including one is desirable.
    :type gpgSignFunc: ``None`` or callable
    :param gpgSignFunc: A function for signing messages.  See
        :func:`bridgedb.crypto.initializeGnuPG` for obtaining a pre-configured
        **gpgSignFunc**.
    :returns: An :class:`EmailResponse` which contains the entire email. To
        obtain the contents of the email, including all headers, simply use
        :meth:`EmailResponse.readContents`.
    """
    response = EmailResponse(gpgSignFunc)
    response.to = client
    response.writeHeaders(fromAddress.encode('utf-8'), str(client), subject,
                          inReplyTo=messageID)
    response.writeBody(body.encode('utf-8'))

    # Only log the email text (including all headers) if SAFE_LOGGING is
    # disabled:
    if not safelog.safe_logging:
        contents = response.readContents()
        logging.debug("Email contents:\n%s" % str(contents))
    else:
        logging.debug("Email text for %r created." % str(client))

    response.rewind()
    return response


class EmailResponse(object):
    """Holds information for generating a response email for a request.

    .. todo:: At some point, we may want to change this class to optionally
        handle creating Multipart MIME encoding messages, so that we can
        include attachments. (This would be useful for attaching our GnuPG
        keyfile, for example, rather than simply pasting it into the body of
        the email.)

    :var _buff: (unicode or buffer) Used internally to write lines for the
        response email into the ``_mailfile``. The reason why both of these
        attributes have two possible types is for the same Python-buggy
        reasons which require :data:`~bridgedb.crypto.NEW_BUFFER_INTERFACE`.
    :var mailfile: (:class:`io.StringIO` or :class:`io.BytesIO`) An in-memory
        file for storing the formatted headers and body of the response email.
    :var str delimiter: Delimiter between lines written to the
        :data:`mailfile`.
    :var bool closed: ``True`` if :meth:`close` has been called.
    :var to: An :api:`twisted.mail.smtp.Address` for the client's email address
        which this response should be sent to.
    """
    _buff = buffer if NEW_BUFFER_INTERFACE else unicode
    mailfile = io.BytesIO if NEW_BUFFER_INTERFACE else io.StringIO

    def __init__(self, gpgSignFunc=None):
        """Create a response to an email we have recieved.

        This class deals with correctly formatting text for the response email
        headers and the response body into an instance of :data:`mailfile`.

        :type gpgSignFunc: ``None`` or callable
        :param gpgSignFunc: A function for signing messages.  See
            :func:`bridgedb.crypto.initializeGnuPG` for obtaining a
            pre-configured **gpgSignFunc**.
        """
        self.gpgSign = gpgSignFunc
        self.mailfile = self.mailfile()
        self.delimiter = '\n'
        self.closed = False
        self.to = None

    def close(self):
        """Close our :data:`mailfile` and set :data:`closed` to ``True``."""
        logging.debug("Closing %s.mailfile..." % (self.__class__.__name__))
        self.mailfile.close()
        self.closed = True

    def read(self, size=None):
        """Read, at most, **size** bytes from our :data:`mailfile`.

        .. note:: This method is required by Twisted's SMTP system.

        :param int size: The number of bytes to read. Defaults to ``None``,
            which reads until EOF.
        :rtype: str
        :returns: The bytes read from the :data:`mailfile`.
        """
        contents = ''
        logging.debug("Reading%s from %s.mailfile..."
                      % ((' {0} bytes'.format(size) if size else ''),
                         self.__class__.__name__))
        try:
            if size is not None:
                contents = self.mailfile.read(int(size)).encode('utf-8')
            else:
                contents = self.mailfile.read().encode('utf-8')
        except Exception as error:  # pragma: no cover
            logging.exception(error)

        return contents

    def readContents(self):
        """Read the all the contents written thus far to the :data:`mailfile`,
        and then :meth:`seek` to return to the original pointer position we
        were at before this method was called.

        :rtype: str
        :returns: The entire contents of the :data:`mailfile`.
        """
        pointer = self.mailfile.tell()
        self.mailfile.seek(0)
        contents = self.mailfile.read()
        self.mailfile.seek(pointer)
        return contents

    def rewind(self):
        """Rewind to the very beginning of the :data:`mailfile`."""
        logging.debug("Rewinding %s.mailfile..." % self.__class__.__name__)
        self.mailfile.seek(0)

    def write(self, line):
        """Write the **line** to the :data:`mailfile`.

        Any **line** written to me will have :data:`delimiter` appended to it
        beforehand.

        :param str line: Something to append into the :data:`mailfile`.
        """
        if line.find('\r\n') != -1:
            # If **line** contains newlines, send it to :meth:`writelines` to
            # break it up so that we can replace them:
            logging.debug("Found newlines in %r. Calling writelines()." % line)
            self.writelines(line)
        else:
            line += self.delimiter
            self.mailfile.write(self._buff(line.encode('utf8')))
            self.mailfile.flush()

    def writelines(self, lines):
        """Calls :meth:`write` for each line in **lines**.

        Line endings of ``'\\r\\n'`` will be replaced with :data:`delimiter`
        (i.e. ``'\\n'``). See :api:`twisted.mail.smtp.SMTPClient.getMailData`
        for the reason.

        :type lines: basestring or list
        :param lines: The lines to write to the :ivar:`mailfile`.
        """
        if isinstance(lines, basestring):
            lines = lines.replace('\r\n', '\n')
            for ln in lines.split('\n'):
                self.write(ln)
        elif isinstance(lines, (list, tuple,)):
            for ln in lines:
                self.write(ln)

    def writeHeaders(self, fromAddress, toAddress, subject=None,
                     inReplyTo=None, includeMessageID=True,
                     contentType='text/plain; charset="utf-8"', **kwargs):
        """Write all headers into the response email.

        :param str fromAddress: The email address for the ``'From:'`` header.
        :param str toAddress: The email address for the ``'To:'`` header.
        :type subject: None or str
        :param subject: The ``'Subject:'`` header.
        :type inReplyTo: None or str
        :param inReplyTo: If set, an ``'In-Reply-To:'`` header will be
            generated. This should be set to the ``'Message-ID:'`` header from
            the client's original request email.
        :param bool includeMessageID: If ``True``, generate and include a
            ``'Message-ID:'`` header for the response.
        :param str contentType: The ``'Content-Type:'`` header.
        :kwargs: If given, the key will become the name of the header, and the
            value will become the Contents of that header.
        """
        self.write("From: %s" % fromAddress)
        self.write("To: %s" % toAddress)
        if includeMessageID:
            self.write("Message-ID: %s" % smtp.messageid().encode('utf-8'))
        if inReplyTo:
            self.write("In-Reply-To: %s" % inReplyTo.encode('utf-8'))
        self.write("Content-Type: %s" % contentType.encode('utf-8'))
        self.write("Date: %s" % smtp.rfc822date().encode('utf-8'))

        if not subject:
            subject = '[no subject]'
        if not subject.lower().startswith('re'):
            subject = "Re: " + subject
        self.write("Subject: %s" % subject.encode('utf-8'))

        if kwargs:
            for headerName, headerValue in kwargs.items():
                headerName = headerName.capitalize()
                headerName = headerName.replace(' ', '-')
                headerName = headerName.replace('_', '-')
                header = "%s: %s" % (headerName, headerValue)
                self.write(header.encode('utf-8'))

        # The first blank line designates that the headers have ended:
        self.write(self.delimiter)

    def writeBody(self, body):
        """Write the response body into the :cvar:`mailfile`.

        If ``EmailResponse.gpgSignFunc`` is set, and signing is configured, the
        **body** will be automatically signed before writing its contents into
        the ``mailfile``.

        :param str body: The body of the response email.
        """
        logging.info("Writing email body...")
        if self.gpgSign:
            logging.info("Attempting to sign email...")
            sig = self.gpgSign(body)
            if sig:
                body = sig
        self.writelines(body)


class SMTPAutoresponder(smtp.SMTPClient):
    """An :api:`twisted.mail.smtp.SMTPClient` for responding to incoming mail.

    The main worker in this class is the :meth:`reply` method, which functions
    to dissect an incoming email from an incoming :class:`SMTPMessage` and
    create a :class:`EmailResponse` email message in reply to it, and then,
    finally, send it out.

    :ivar log: A :api:`twisted.python.util.LineLog` cache of messages.
    :ivar debug: If ``True``, enable logging (accessible via :ivar:`log`).
    :ivar str identity: Our FQDN which will be sent during client ``HELO``.
    :ivar incoming: An incoming
        :api:`Message <twisted.mail.smtp.rfc822.Message>`, i.e. as returned
        from :meth:`SMTPMessage.getIncomingMessage`.
    :ivar deferred: A :api:`Deferred <twisted.internet.defer.Deferred>` with
       registered callbacks, :meth:`sentMail` and :meth:`sendError`, which
       will be given to the reactor in order to process the sending of the
       outgoing response email.
    """
    debug = True
    identity = smtp.DNSNAME

    def __init__(self):
        """Handle responding (or not) to an incoming email."""
        smtp.SMTPClient.__init__(self, self.identity)
        self.incoming = None
        self.deferred = defer.Deferred()
        self.deferred.addCallback(self.sentMail)
        self.deferred.addErrback(self.sendError)

    def getMailData(self):
        """Gather all the data for building the response to the client.

        This method must return a file-like object containing the data of the
        message to be sent. Lines in the file should be delimited by ``\\n``.

        :rtype: ``None`` or :class:`EmailResponse`
        :returns: An ``EmailResponse``, if we have a response to send in reply
            to the incoming email, otherwise, returns ``None``.
        """
        clients = self.getMailTo()
        if not clients: return
        client = clients[0]  # There should have been only one anyway

        # Log the email address that this message came from if SAFELOGGING is
        # not enabled:
        if not safelog.safe_logging:
            logging.debug("Incoming email was from %s ..." % client)

        if not self.runChecks(client): return

        recipient = self.getMailFrom()
        # Look up the locale part in the 'To:' address, if there is one, and
        # get the appropriate Translation object:
        lang = translations.getLocaleFromPlusAddr(recipient)
        logging.info("Client requested email translation: %s" % lang)

        body = createResponseBody(self.incoming.lines,
                                  self.incoming.context,
                                  client, lang)
        if not body: return  # The client was already warned.

        messageID = self.incoming.message.getheader("Message-ID", None)
        subject = self.incoming.message.getheader("Subject", None)
        response = generateResponse(recipient, client,
                                    body, subject, messageID,
                                    self.incoming.context.gpgSignFunc)
        return response

    def getMailTo(self):
        """Attempt to get the client's email address from an incoming email.

        :rtype: list
        :returns: A list containing the client's
            :func:`normalized <bridgedb.parse.addr.normalizeEmail>` email
            :api:`Address <twisted.mail.smtp.Address>`, if it originated from
            a domain that we accept and the address was well-formed. Otherwise,
            returns ``None``. Even though we're likely to respond to only one
            client at a time, the return value of this method must be a list
            in order to hook into the rest of
            :api:`twisted.mail.smtp.SMTPClient` correctly.
        """
        clients = []
        addrHeader = None
        try: fromAddr = self.incoming.message.getaddr("From")[1]
        except (IndexError, TypeError, AttributeError): pass
        else: addrHeader = fromAddr

        if not addrHeader:
            logging.warn("No From header on incoming mail.")
            try: senderHeader = self.incoming.message.getaddr("Sender")[1]
            except (IndexError, TypeError, AttributeError): pass
            else: addrHeader = senderHeader
        if not addrHeader:
            logging.warn("No Sender header on incoming mail.")
            return clients

        client = None
        try:
            if addrHeader in self.incoming.context.whitelist.keys():
                logging.debug("Email address was whitelisted: %s."
                              % addrHeader)
                client = smtp.Address(addrHeader)
            else:
                normalized = addr.normalizeEmail(
                    addrHeader,
                    self.incoming.context.domainMap,
                    self.incoming.context.domainRules)
                client = smtp.Address(normalized)
        except (addr.UnsupportedDomain) as error:
            logging.warn(error)
        except (addr.BadEmail, smtp.AddressError) as error:
            logging.warn(error)

        if client:
            clients.append(client)

        return clients

    def getMailFrom(self):
        """Find our address in the recipients list of the **incoming** message.

        :rtype: str
        :return: Our address from the recipients list. If we can't find it
            return our default ``EMAIL_FROM_ADDRESS`` from the config file.
        """
        logging.debug("Searching for our email address in 'To:' header...")

        ours = None

        try:
            ourAddress = smtp.Address(self.incoming.context.fromAddr)
            allRecipients = self.incoming.message.getaddrlist("To")

            for _, addr in allRecipients:
                recipient = smtp.Address(addr)
                if not ourAddress.domain in recipient.domain:
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
                # Only check the username before the first '+':
                beforePlus = recipient.local.split('+', 1)[0]
                if beforePlus == ourAddress.local:
                    ours = str(recipient)
            if not ours:
                raise addr.BadEmail(allRecipients)

        except Exception as error:
            logging.error(("Couldn't find our email address in incoming email "
                           "headers: %r" % error))
            # Just return the email address that we're configured to use:
            ours = self.incoming.context.fromAddr

        logging.debug("Found our email address: %s." % ours)
        return ours

    def sentMail(self, success):
        """Callback for a :api:`twisted.mail.smtp.SMTPSenderFactory`,
        called when an attempt to send an email is completed.

        If some addresses were accepted, code and resp are the response
        to the DATA command. If no addresses were accepted, code is -1
        and resp is an informative message.

        :param int code: The code returned by the SMTP Server.
        :param str resp: The string response returned from the SMTP Server.
        :param int numOK: The number of addresses accepted by the remote host.
        :param list addresses: A list of tuples (address, code, resp) listing
            the response to each ``RCPT TO`` command.
        :param log: The SMTP session log. (We don't use this, but it is sent
            by :api:`twisted.mail.smtp.SMTPSenderFactory` nonetheless.)
        """
        numOk, addresses = success

        for (address, code, resp) in addresses:
            logging.info("Sent reply to %s" % address)
            logging.debug("SMTP server response: %d %s" % (code, resp))

        if self.debug:
            for line in self.log.log:
                if line:
                    logging.debug(line)

    def sendError(self, fail):
        """Errback for a :api:`twisted.mail.smtp.SMTPSenderFactory`.

        :param fail: A :api:`twisted.python.failure.Failure` or a
            :api:`twisted.mail.smtp.SMTPClientError` which occurred during the
            transaction to send the outgoing email.
        """
        logging.debug("called with %r" % fail)

        if isinstance(fail, failure.Failure):
            error = fail.getTraceback() or "Unknown"
        elif isinstance(fail, Exception):
            error = fail
        logging.error(error)

        try:
            # This handles QUIT commands, disconnecting, and closing the
            # transport:
            smtp.SMTPClient.sendError(self, fail)
        # We might not have `transport` and `protocol` attributes, depending
        # on when and where the error occurred, so just catch and log it:
        except Exception as error:
            logging.error(error)

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

        response = self.getMailData()
        if not response:
            return self.deferred

        return self.send(response)

    def runChecks(self, client):
        """Run checks on the incoming message, and only reply if they pass.

        1. Check if the client's address is whitelisted.

        2. If it's not whitelisted, check that the domain names, taken from
        the SMTP ``MAIL FROM:`` command and the email ``'From:'`` header, can
        be :func:`canonicalized <addr.canonicalizeEmailDomain>`.

        3. Check that those canonical domains match.

        4. If the incoming message is from a domain which supports DKIM
        signing, then run :func:`bridgedb.email.dkim.checkDKIM` as well.

        .. note:: Calling this method sets the ``canonicalFromEmail`` and
            :data:``canonicalDomainRules`` attributes of the :data:`incoming`
            message.

        :param client: An :api:`twisted.mail.smtp.Address`, which contains
            the client's email address, extracted from the ``'From:'`` header
            from the incoming email.
        :rtype: bool
        :returns: ``False`` if the checks didn't pass, ``True`` otherwise.
        """
        # If the SMTP ``RCPT TO:`` domain name couldn't be canonicalized, then
        # we *should* have bailed at the SMTP layer, but we'll reject this
        # email again nonetheless:
        if not self.incoming.canonicalFromSMTP:
            logging.warn(("SMTP 'MAIL FROM' wasn't from a canonical domain "
                          "for email from %s") % str(client))
            return False

        # Allow whitelisted addresses through the canonicalization check:
        if str(client) in self.incoming.context.whitelist.keys():
            self.incoming.canonicalFromEmail = client.domain
            logging.info("'From:' header contained whitelisted address: %s"
                         % str(client))
        else:
            logging.debug("Canonicalizing client email domain...")
            try:
                # The client's address was already checked to see if it came
                # from a supported domain and is a valid email address in
                # :meth:`getMailTo`, so we should just be able to re-extract
                # the canonical domain safely here:
                self.incoming.canonicalFromEmail = canonicalizeEmailDomain(
                    client.domain, self.incoming.canon)
                logging.debug("Canonical email domain: %s"
                              % self.incoming.canonicalFromEmail)
            except addr.UnsupportedDomain as error:
                logging.info("Domain couldn't be canonicalized: %s"
                             % safelog.logSafely(client.domain))
                return False

        # The canonical domains from the SMTP ``MAIL FROM:`` and the email
        # ``From:`` header should match:
        #if self.incoming.canonicalFromSMTP != self.incoming.canonicalFromEmail:
        #    logging.error("SMTP/Email canonical domain mismatch!")
        #    logging.debug("Canonical domain mismatch: %s != %s"
        #                  % (self.incoming.canonicalFromSMTP,
        #                     self.incoming.canonicalFromEmail))
        #    return False

        self.incoming.domainRules = self.incoming.context.domainRules.get(
            self.incoming.canonicalFromEmail, list())

        # If the domain's ``domainRules`` say to check DKIM verification
        # results, and those results look bad, reject this email:
        if not dkim.checkDKIM(self.incoming.message, self.incoming.domainRules):
            return False

        # If fuzzy matching is enabled via the EMAIL_FUZZY_MATCH setting, then
        # calculate the Levenshtein String Distance (see
        # :func:`~bridgedb.util.levenshteinDistance`):
        if self.incoming.context.fuzzyMatch != 0:
            for blacklistedAddress in self.incoming.context.blacklist:
                distance = levenshteinDistance(self.incoming.canonicalFromEmail,
                                               blacklistedAddress)
                if distance <= self.incoming.context.fuzzyMatch:
                    logging.info("Fuzzy-matched %s to blacklisted address %s!"
                                 % (self.incoming.canonicalFromEmail,
                                    blacklistedAddress))
                    return False

        return True

    def send(self, response, retries=0, timeout=30, reaktor=reactor):
        """Send our **response** in reply to :data:`incoming`.

        :type client: :api:`twisted.mail.smtp.Address`
        :param client: The email address of the client.
        :param response: A :class:`EmailResponse`.
        :param int retries: Try resending this many times. (default: ``0``)
        :param int timeout: Timeout after this many seconds. (default: ``30``)
        :rtype: :api:`Deferred <twisted.internet.defer.Deferred>`
        :returns: Our :data:`deferred`.
        """
        logging.info("Sending reply to %s ..." % str(response.to))

        factory = smtp.SMTPSenderFactory(self.incoming.context.smtpFromAddr,
                                         str(response.to),
                                         response,
                                         self.deferred,
                                         retries=retries,
                                         timeout=timeout)
        factory.domain = smtp.DNSNAME
        reaktor.connectTCP(self.incoming.context.smtpServerIP,
                           self.incoming.context.smtpServerPort,
                           factory)
        return self.deferred
