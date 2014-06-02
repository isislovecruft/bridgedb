# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013, Isis Lovecruft
#             (c) 2007-2013, The Tor Project, Inc.
#             (c) 2007-2013, all entities within the AUTHORS file
# :license: 3-Clause BSD, see LICENSE for licensing information

"""Unittests for the :mod:`bridgedb.email.server` module."""

from __future__ import print_function

import io
import copy
import os
import shutil
import socket
import types

from bridgedb.Dist import EmailBasedDistributor
from bridgedb.email import server
from bridgedb.parse.addr import BadEmail
from bridgedb.persistent import Conf
from bridgedb.schedule import Unscheduled
from bridgedb.test.test_HTTPServer import DummyBridge
from bridgedb.test.util import fileCheckDecorator
from bridgedb.test.util import TestCaseMixin

from twisted.python import log
from twisted.internet import defer
from twisted.internet import reactor
from twisted.mail.smtp import SMTPBadRcpt
from twisted.mail.smtp import SMTPBadSender
from twisted.mail.smtp import User
from twisted.mail.smtp import Address
from twisted.test import proto_helpers
from twisted.trial import unittest




class CheckDKIMTests(unittest.TestCase):
    """Tests for :func:`email.server.checkDKIM`."""

    def setUp(self):
        """Create fake email, distributor, and associated context data."""
        self.goodMessage = io.StringIO(unicode("""\
From: user@gmail.com
To: bridges@localhost
X-DKIM-Authentication-Results: pass
Subject: testing

get bridges
"""))
        self.badMessage = io.StringIO(unicode("""\
From: user@gmail.com
To: bridges@localhost
Subject: testing

get bridges
"""))
        self.config = _createConfig()
        self.domainRules = self.config.EMAIL_DOMAIN_RULES

    def test_checkDKIM_good(self):
        message = server.smtp.rfc822.Message(self.goodMessage)
        self.assertTrue(server.checkDKIM(message,
                                         self.domainRules.get("gmail.com")))

    def test_checkDKIM_bad(self):
        message = server.smtp.rfc822.Message(self.badMessage)
        result = server.checkDKIM(message, self.domainRules.get("gmail.com"))
        self.assertIs(result, False)


class CreateResponseBodyTests(unittest.TestCase):
    """Tests for :func:`bridgedb.email.server.createResponseBody`."""

    def _moveGPGTestKeyfile(self):
        here          = os.getcwd()
        topDir        = here.rstrip('_trial_temp')
        self.gpgFile  = os.path.join(topDir, 'gnupghome', 'TESTING.subkeys.sec')
        self.gpgMoved = os.path.join(here, 'TESTING.subkeys.sec')
        shutil.copy(self.gpgFile, self.gpgMoved)

    def setUp(self):
        """Create fake email, distributor, and associated context data."""
        self._moveGPGTestKeyfile()
        self.toAddress = "user@example.com"
        self.config = _createConfig()
        self.ctx = _createMailContext(self.config)
        self.distributor = self.ctx.distributor

    def _getIncomingLines(self, clientAddress="user@example.com"):
        """Generate the lines of an incoming email from **clientAddress**."""
        self.toAddress = server.smtp.Address(clientAddress)
        lines = [
            "From: %s" % clientAddress,
            "To: bridges@localhost",
            "Subject: testing",
            "",
            "get bridges",
        ]
        return lines

    def test_createResponseBody_getKey(self):
        """A request for 'get key' should receive our GPG key."""
        lines = self._getIncomingLines()
        lines[4] = "get key"
        ret = server.createResponseBody(lines, self.ctx, self.toAddress)
        self.assertSubstring('-----BEGIN PGP PUBLIC KEY BLOCK-----', ret)

    def test_createResponseBody_bridges_invalid(self):
        """An invalid request for 'transport obfs3' should get help text."""
        lines = self._getIncomingLines("testing@localhost")
        lines[4] = "transport obfs3"
        ret = server.createResponseBody(lines, self.ctx, self.toAddress)
        self.assertSubstring("COMMANDs", ret)

    def test_createResponseBody_bridges_obfs3(self):
        """A request for 'get transport obfs3' should receive a response."""
        lines = self._getIncomingLines("testing@localhost")
        lines[4] = "get transport obfs3"
        ret = server.createResponseBody(lines, self.ctx, self.toAddress)
        self.assertSubstring("Here are your bridges", ret)
        self.assertSubstring("obfs3", ret)

    def test_createResponseBody_bridges_obfsobfswebz(self):
        """We should only pay attention to the *last* in a crazy request."""
        lines = self._getIncomingLines("testing@localhost")
        lines[4] = "get unblocked webz"
        lines.append("get transport obfs2")
        lines.append("get transport obfs3")
        ret = server.createResponseBody(lines, self.ctx, self.toAddress)
        self.assertSubstring("Here are your bridges", ret)
        self.assertSubstring("obfs3", ret)

    def test_createResponseBody_bridges_obfsobfswebzipv6(self):
        """We should *still* only pay attention to the *last* request."""
        lines = self._getIncomingLines("testing@localhost")
        lines[4] = "transport obfs3"
        lines.append("get unblocked webz")
        lines.append("get ipv6")
        lines.append("get transport obfs2")
        ret = server.createResponseBody(lines, self.ctx, self.toAddress)
        self.assertSubstring("Here are your bridges", ret)
        self.assertSubstring("obfs2", ret)


class MailResponseTests(unittest.TestCase):
    """Tests for ``generateResponse()`` and ``MailResponse``."""

    def setUp(self):
        self.fromAddr = "bridges@torproject.org"
        self.clientAddr = "user@example.com"
        self.body = """\
People think that time is strictly linear, but, in reality, it's actually just
a ball of timey-wimey, wibbly-warbly... stuff."""

    def tearDown(self):
        server.safelog.safe_logging = True

    def test_MailResponse_generateResponse(self):
        response = server.generateResponse(self.fromAddr, self.clientAddr,
                                           self.body)
        self.assertIsInstance(response, server.MailResponse)

    def test_MailResponse_generateResponse_noSafelog(self):
        server.safelog.safe_logging = False
        response = server.generateResponse(self.fromAddr, self.clientAddr,
                                           self.body)
        self.assertIsInstance(response, server.MailResponse)

    def test_MailResponse_generateResponse_mailfile(self):
        response = server.generateResponse(self.fromAddr, self.clientAddr,
                                           self.body)
        self.assertIsInstance(response.mailfile, (io.BytesIO, io.StringIO))

    def test_MailResponse_generateResponse_withInReplyTo(self):
        response = server.generateResponse(self.fromAddr, self.clientAddr,
                                           self.body, messageID="NSA")
        contents = str(response.readContents()).replace('\x00', '')
        self.assertIsInstance(response.mailfile, (io.BytesIO, io.StringIO))
        self.assertSubstring("In-Reply-To: NSA", contents)

    def test_MailResponse_generateResponse_readContents(self):
        response = server.generateResponse(self.fromAddr, self.clientAddr,
                                           self.body)
        contents = str(response.readContents()).replace('\x00', '')
        self.assertSubstring('timey-wimey, wibbly-warbly... stuff.', contents)

    def test_MailResponse_additionalHeaders(self):
        response = server.MailResponse()
        response.writeHeaders(self.fromAddr, self.clientAddr,
                              subject="Re: echelon", inReplyTo="NSA",
                              X_been_there="They were so 2004")
        contents = str(response.readContents()).replace('\x00', '')
        self.assertIsInstance(response.mailfile, (io.BytesIO, io.StringIO))
        self.assertSubstring("In-Reply-To: NSA", contents)
        self.assertSubstring("X-been-there: They were so 2004", contents)

    def test_MailResponse_close(self):
        """Calling MailResponse.close() should close the ``mailfile`` and set
        ``closed=True``.
        """
        response = server.MailResponse()
        self.assertEqual(response.closed, False)
        response.close()
        self.assertEqual(response.closed, True)
        self.assertRaises(ValueError, response.write, self.body)

    def test_MailResponse_write(self):
        """Calling MailResponse.write() should write to the mailfile."""
        response = server.MailResponse()
        response.write(self.body)
        contents = str(response.readContents()).replace('\x00', '')
        self.assertEqual(self.body.replace('\n', '\r\n') + '\r\n', contents)

    def test_MailResponse_writelines(self):
        """Calling MailResponse.writelines() with a list should write the
        concatenated contents of the list into the mailfile.
        """
        response = server.MailResponse()
        response.writelines(self.body.split('\n'))
        contents = str(response.readContents()).replace('\x00', '')
        self.assertEqual(self.body.replace('\n', '\r\n') + '\r\n', contents)


class MailMessageTests(unittest.TestCase):
    """Unittests for :class:`bridgedb.email.server.MailMessage`."""

    def setUp(self):
        self.config = _createConfig()
        self.context = _createMailContext(self.config)
        self.message = server.MailMessage(self.context)

    def _getIncomingLines(self, clientAddress="user@example.com"):
        """Generate the lines of an incoming email from **clientAddress**."""
        lines = [
            "From: %s" % clientAddress,
            "To: bridges@localhost",
            "Subject: testing",
            "",
            "get bridges",
        ]
        self.message.lines = lines

    def test_MailMessage_getMailFrom_notbridgedb_at_yikezors_dot_net(self):
        """MailMessage.getMailFrom() for an incoming email sent to any email
        address other than the one we're listening for should return our
        configured address, not the one in the incoming email.
        """
        self._getIncomingLines()
        self.message.lines[1] = 'To: notbridgedb@yikezors.net'
        incoming = self.message.getIncomingMessage()
        recipient = str(self.message.getMailFrom(incoming))
        self.assertEqual(recipient, self.context.fromAddr)

    def test_MailMessage_getMailFrom_givemebridges_at_seriously(self):
        """MailMessage.getMailFrom() for an incoming email sent to any email
        address other than the one we're listening for should return our
        configured address, not the one in the incoming email.
        """
        self._getIncomingLines()
        self.message.lines[1] = 'To: givemebridges@serious.ly'
        incoming = self.message.getIncomingMessage()
        recipient = str(self.message.getMailFrom(incoming))
        self.assertEqual(recipient, self.context.fromAddr)

    def test_MailMessage_getMailFrom_bad_address(self):
        """MailMessage.getMailFrom() for an incoming email sent to a malformed
        email address should log an smtp.AddressError and then return our
        configured email address.
        """
        self._getIncomingLines()
        self.message.lines[1] = 'To: ><@><<<>>.foo'
        incoming = self.message.getIncomingMessage()
        recipient = str(self.message.getMailFrom(incoming))
        self.assertEqual(recipient, self.context.fromAddr)

    def test_MailMessage_reply_noFrom(self):
        """A received email without a "From:" or "Sender:" header shouldn't
        receive a response.
        """
        self._getIncomingLines()
        self.message.lines[0] = ""
        ret = self.message.reply()
        self.assertIsInstance(ret, defer.Deferred)

    def test_MailMessage_reply_badAddress(self):
        """Don't respond to RFC2822 malformed source addresses."""
        self._getIncomingLines("testing*.?\"@example.com")
        ret = self.message.reply()
        self.assertIsInstance(ret, defer.Deferred)

    def test_MailMessage_reply_anotherBadAddress(self):
        """Don't respond to RFC2822 malformed source addresses."""
        self._getIncomingLines("Mallory <>>@example.com")
        ret = self.message.reply()
        self.assertIsInstance(ret, defer.Deferred)

    def test_MailMessage_reply_invalidDomain(self):
        """Don't respond to RFC2822 malformed source addresses."""
        self._getIncomingLines("testing@exa#mple.com")
        ret = self.message.reply()
        self.assertIsInstance(ret, defer.Deferred)

    def test_MailMessage_reply_anotherInvalidDomain(self):
        """Don't respond to RFC2822 malformed source addresses."""
        self._getIncomingLines("testing@exam+ple.com")
        ret = self.message.reply()
        self.assertIsInstance(ret, defer.Deferred)

    def test_MailMessage_reply_DKIM_badDKIMheader(self):
        """An email with an 'X-DKIM-Authentication-Result:' header appended
        after the body should not receive a response.
        """
        self._getIncomingLines("testing@gmail.com")
        self.message.lines.append("X-DKIM-Authentication-Result: ")
        ret = self.message.reply()
        self.assertIsInstance(ret, defer.Deferred)

    def test_MailMessage_reply_goodDKIMheader(self):
        """An email with a good DKIM header should be responded to."""
        self._getIncomingLines("testing@gmail.com")
        self.message.lines.insert(3, "X-DKIM-Authentication-Result: pass")
        ret = self.message.reply()
        self.assertIsInstance(ret, defer.Deferred)

    def test_MailMessage_reply_transport_invalid(self):
        """An invalid request for 'transport obfs3' should get help text."""
        self.skip = True
        raise unittest.SkipTest("We need to fake the reactor for this one")

        self._getIncomingLines("testing@example.com")
        self.message.lines[4] = "transport obfs3"
        ret = self.message.reply()
        self.assertSubstring("COMMANDs", ret)

    def test_MailMessage_reply_transport_valid(self):
        """An valid request for 'get transport obfs3' should get obfs3."""
        self.skip = True
        raise unittest.SkipTest("We need to fake the reactor for this one")

        self._getIncomingLines("testing@example.com")
        self.message.lines[4] = "transport obfs3"
        ret = self.message.reply()
        self.assertIsInstance(ret, defer.Deferred)
        self.assertSubstring("obfs3", ret)
        return ret


class MailDeliveryTests(unittest.TestCase):
    """Unittests for :class:`email.server.MailDelivery`."""

    def setUp(self):
        """Set up our :class:`server.MailDelivery` instance, and reset the
        following ``TestCase`` attributes to ``None``:
            - ``helo``
            - ``proto``
            - ``origin``
            - ``user``
        """
        self.config = _createConfig()
        self.context = _createMailContext(self.config)
        self.delivery = server.MailDelivery()

        self.helo = None
        self.proto = None
        self.origin = None
        self.user = None

    def tearDown(self):
        """Reset all TestCase instance attributes between each test run."""
        self.helo = None
        self.proto = None
        self.origin = None
        self.user = None

    def _createProtocolWithHost(self, host):
        """Mock a Protocol which has a ``host`` attribute.

        We don't currently use any of the ``IProtocol`` methods of the
        returned ``twisted.test.proto_helpers.AccumulatingProtocol``, and so
        this could be any class, although a mocked ``IProtocol`` implementer
        was chosen for completeness and realism's sakes.

        :param str host: A domain name or IP address.
        :rtype: :api:`twisted.test.proto_helpers.AccumulatingProtocol`
        :returns: A Protocol instance which has its ``host`` attribute set to
            the given **host**, so that an :api:`twisted.mail.smtp.User` can
            be constructed with it.
        """
        self.proto = proto_helpers.AccumulatingProtocol()
        self.proto.host = host

    def _createUser(self, username, domain, ipaddress):
        """Create a ``twisted.mail.smtp.User`` for testing.

        :param str username: The local part of the client's email address.
        :param str domain: The host part of the client's email address.
        :param str ipaddress: The IP address of the client's mail server.
        """
        self.helo = (domain, ipaddress)
        self._createProtocolWithHost(domain)
        self.origin = Address('@'.join((username, domain,)))
        self.user = User(username, self.helo, self.proto, self.origin)

    def _setUpMAILFROM(self):
        """Set up the parameters for emulating a connected client sending a
        SMTP 'MAIL FROM:' command to us.

        The default is to emulate sending: ``MAIL FROM: client@example.com``.
        """
        self.helo = ('localhost', '127.0.0.1')
        self.origin = server.smtp.Address('client@example.com')
        self.delivery.setBridgeDBContext(self.context)

    def _setUpRCPTTO(self, username=None):
        """Set up the parameters for emulating a connected client sending a
        SMTP 'RCPT TO:' command to us.

        The default is to emulate sending: ``RCPT TO: bridges@localhost``.
        """
        name = username if username is not None else self.config.EMAIL_USERNAME
        self._createUser(name, 'localhost', '127.0.0.1')
        self.delivery.setBridgeDBContext(self.context)

    def test_MailDelivery_init(self):
        """After calling :meth:`server.MailDelivery.__init__`, we should have a
        :class:`server.MailDelivery` object instance.
        """
        self.assertIsInstance(self.delivery, server.MailDelivery)

    def test_MailDelivery_setBridgeDBContext(self):
        """Calling :meth:`server.MailDelivery.setBridgeDBContext` should set
        the :ivar:`MailDelivery.context` attribute.

        The ``MailDelivery.context`` should be a :class:`server.MailContext`,
        and it should have relevant settings from the config file stored
        within it.
        """
        self.delivery.setBridgeDBContext(self.context)
        self.assertIsInstance(self.delivery.context, server.MailContext)
        self.assertEqual(self.delivery.context.smtpFromAddr,
                         self.config.EMAIL_SMTP_FROM_ADDR)

    def test_MailDelivery_receivedHeader(self):
        """The email resulting from a MailDelivery, the latter received from
        ``'client@example.com'`` should contain a header stating:
        ``'Received: from example.com'``.
        """
        self._createUser('client', 'example.com', '127.0.0.1')
        hdr = self.delivery.receivedHeader(self.helo, self.origin, [self.user,])
        self.assertSubstring("Received: from example.com", hdr)

    def test_MailDelivery_validateFrom(self):
        """A valid origin should be stored as ``MailDelivery.fromCanonical``."""
        self._setUpMAILFROM()
        self.delivery.validateFrom(self.helo, self.origin)
        self.assertEqual(self.delivery.fromCanonical, 'example.com')

    def test_MailDelivery_validateFrom_unsupportedDomain(self):
        """A domain not in our canon should raise a SMTPBadSender."""
        self._setUpMAILFROM()
        origin = server.smtp.Address('throwing.pickles@yo.mama')
        self.assertRaises(SMTPBadSender,
                          self.delivery.validateFrom, self.helo, origin)

    def test_MailDelivery_validateFrom_origin_notAdressType(self):
        """A non ``twisted.mail.smtp.Address`` origin should raise an
        AttributeError exception.
        """
        self._setUpMAILFROM()
        origin = 'throwing.pickles@yo.mama'
        self.delivery.validateFrom(self.helo, origin)

    def test_MailDelivery_validateTo(self):
        """Should return a callable that results in a MailMessage."""
        self._setUpRCPTTO()
        validated = self.delivery.validateTo(self.user)
        self.assertIsInstance(validated, types.FunctionType)
        self.assertIsInstance(validated(), server.MailMessage)

    def test_MailDelivery_validateTo_plusAddress(self):
        """Should return a callable that results in a MailMessage."""
        self._setUpRCPTTO('bridges+ar')
        validated = self.delivery.validateTo(self.user)
        self.assertIsInstance(validated, types.FunctionType)
        self.assertIsInstance(validated(), server.MailMessage)

    def test_MailDelivery_validateTo_badUsername(self):
        """A :class:`server.MailDelivery` which sends a SMTP
        ``RCPT TO: yo.mama@localhost`` should raise a
        ``twisted.mail.smtp.SMTPBadRcpt`` exception.
        """
        self._setUpRCPTTO('yo.mama')
        self.assertRaises(SMTPBadRcpt, self.delivery.validateTo, self.user)


class SMTPTestCaseMixin(TestCaseMixin):
    """Utility methods for use within any subclasses of
    :api:`twisted.trial.unittest.TestCase` which test SMTP.

    To use me, subclass :api:`twisted.trial.unittest.TestCase` and mix me into
    the middle of your class inheritance declarations, like so::

        class ExampleSMTPTests(SMTPTestCaseMixin, unittest.TestCase):
            pass

    and then make certain that your ``TestCase`` subclass has its ``proto``
    and attribute assigned properly::

        class ExampleSMTPTests(SMTPTestCaseMixin, unittest.TestCase):
            def setUp(self):
                factory = twisted.mail.smtp.SMTPFactory()
                self.proto = self.factory.buildProtocol(('127.0.0.1', 0))


    :ivar proto: A :api:`Protocol <twisted.internet.protocol.Protocol>`
        associated with a
        :api:`ServerFactory <twisted.internet.protocol.ServerFactory>`.
    :ivar transport: Anything that implements
        :api:`ITransport <twisted.internet.interfaces.ITransport>`. The default
        is a :api:`twisted.test.proto_helpers.StringTransportWithDisconection`.
    :ivar str smtpFromAddr: The default email address for the server.
    """

    proto = None
    transport = proto_helpers.StringTransportWithDisconnection()
    smtpFromAddr = None

    def tearDown(self):
        """Cleanup method after each ``test_*`` method runs; removes timed out
        connections on the reactor and clears the :ivar:`transport`.
        """
        self.transport.clear()  # Clear bytes from the transport.

        for delay in reactor.getDelayedCalls():
            try:
                delay.cancel()
            except (AlreadyCalled, AlreadyCancelled):
                pass

    def _buildEmail(self, fromAddr=None, toAddr=None, subject=None, body=None):
        """Creates email text (including headers) for use in an SMTP DATA
         segment. Includes the SMTP DATA EOM command ('.') at the end. If no
         keyword arguments are given, the defaults are fairly sane.

        Suitable for testing a :class:`bridgedb.email.server.MailFactory`.

        :param str fromAddr: An email address for the 'From:' header.
        :param str toAddr: An email address for the 'To:' header.
        :param str subject: The contents of the 'Subject:' header.
        :param str body: The contents of the email body.
        :rtype: str
        :returns: The email text.
        """
        fromAddr = fromAddr if fromAddr else 'testing@localhost'
        toAddr = toAddr if toAddr else self.smtpFromAddr
        subject = subject if subject else 'testing testing one two three'
        body = body if body else 'get bridges'

        contents = ['From: %s' % fromAddr,
                    'To: %s' % toAddr,
                    'Subject: %s' % subject,
                    '\r\n %s' % body,
                    '.']  # SMTP DATA EOM command
        emailText = self.proto.delimiter.join(contents)
        return emailText

    def _buildSMTP(self, commands):
        """Format a list of SMTP protocol commands into a string, using the proper
         protocol delimiter.

        :param list commands: A list of raw SMTP-protocol command lines.
        :rtype: str
        :returns: The string for sending those **commands**, suitable for
            giving to a :api:`twisted.internet.Protocol.dataReceived` method.
        """
        data = self.proto.delimiter.join(commands) + self.proto.delimiter
        return data

    def _test(self, commands, expected, noisy=False):
        """Send the SMTP **commands** to the ``dataReceived`` method of your
         TestCase's protocol (this must be the `proto` attribute of your
         `TestCase`, i.e. this uses ``TestCase.proto.dataReceived``). Next,
         check that the substring which is **expected** to be within the
         server's output matches what was received from :ivar`transport`.

        :param list commands: A sequence of raw SMTP command lines. This will
            automatically be passed to :meth:`_buildSMTP`.
        :param str expected: A substring which should occur in the "server"
            output (taken from the :ivar:`transport`).
        :param bool noisy: If ``True``, print the conversation between the
            "client" and the "server" in a nicely formatted manner.
        """
        data = self._buildSMTP(commands)
        self.proto.dataReceived(data)
        recv = self.transport.value()

        if noisy:
            client = data.replace('\r\n', '\r\n ')
            server = recv.replace('\r\n', '\r\n\t\t ')
            print('\n CLIENT --------->', '\n %s' % client)
            print('\t\t', '<--------- SERVER', '\n\t\t %s' % server)

        self.assertSubstring(expected, recv)


class MailFactoryTests(SMTPTestCaseMixin, unittest.TestCase):
    """Unittests for :class:`bridgedb.email.server.MailFactory`."""

    def setUp(self):
        """Set up a localhost MailFactory handler incoming SMTP connections."""
        config = _createConfig()
        context = _createMailContext(config)
        factory = server.MailFactory(context)
        factory.protocol.timeout = None  # Otherwise the reactor gets dirty

        self.smtpFromAddr = context.smtpFromAddr  # 'bridges@localhost'
        self.proto = factory.buildProtocol(('127.0.0.1', 0))
        self.transport = proto_helpers.StringTransportWithDisconnection()
        self.proto.setTimeout(None)
        # Set the protocol; StringTransportWithDisconnection is a bit janky:
        self.transport.protocol = self.proto
        self.proto.makeConnection(self.transport)

    def test_MailFactory_HELO_localhost(self):
        """Send 'HELO localhost' to the server's transport."""
        ip = self.transport.getPeer().host
        self._test(['HELO localhost'],
                   "Hello %s, nice to meet you" % ip)

    def test_MailFactory_MAIL_FROM_testing_at_localhost(self):
        """Send 'MAIL FROM: human@localhost'."""
        self._test(['HELO localhost',
                    'MAIL FROM: testing@localhost'],
                   "250 Sender address accepted")

    def test_MailFactory_MAIL_FROM_testing_at_gethostname(self):
        """Send 'MAIL FROM: human@hostname' for the local hostname."""
        hostname = socket.gethostname() or "computer"
        self._test(['HELO localhost',
                    'MAIL FROM: testing@%s' % hostname],
                   "250 Sender address accepted")

    def test_MailFactory_MAIL_FROM_testing_at_ipaddress(self):
        """Send 'MAIL FROM: human@ipaddr' for the loopback IP address."""
        hostname = socket.gethostbyname(socket.gethostname()) or "127.0.0.1"
        self._test(['HELO localhost',
                    'MAIL FROM: testing@%s' % hostname],
                   "250 Sender address accepted")

    def test_MailFactory_RCPT_TO_config_EMAIL_SMTP_FROM_ADDR(self):
        """Send 'RCPT TO:' with the context.smtpFromAddr."""
        self._test(['HELO localhost',
                    'MAIL FROM: testing@localhost',
                    'RCPT TO: %s' % self.smtpFromAddr],
                   "250 Recipient address accepted")

    def test_MailFactory_DATA_blank(self):
        """A DATA command with nothing after it should receive::
            '354 Continue'
        in response.
        """
        self._test(['HELO localhost',
                    'MAIL FROM: testing@localhost',
                    'RCPT TO: %s' % self.smtpFromAddr,
                    "DATA"],
                   "354 Continue")

    def test_MailFactory_DATA_get_help(self):
        """A DATA command with ``'get help'`` in the email body should
        receive::
            '250 Delivery in progress'
        in response.
        """
        emailText = self._buildEmail(body="get help")
        self._test(['HELO localhost',
                    'MAIL FROM: testing@localhost',
                    'RCPT TO: %s' % self.smtpFromAddr,
                    "DATA", emailText],
                   "250 Delivery in progress",
                   noisy=True)

    def test_MailFactory_DATA_get_transport_obfs3(self):
        """A DATA command with ``'get transport obfs3'`` in the email body
        should receive::
            '250 Delivery in progress'
        in response.
        """
        emailText = self._buildEmail(body="get transport obfs3")
        self._test(['HELO localhost',
                    'MAIL FROM: testing@localhost',
                    'RCPT TO: %s' % self.smtpFromAddr,
                    "DATA", emailText],
                   "250 Delivery in progress",
                   noisy=True)

    def test_MailFactory_DATA_To_bridges_plus_zh_CN(self):
        """Test sending to 'bridges+zh_CN' address for Chinese translations."""
        # TODO: Add tests which use '+' syntax in mailTo in order to test
        # email translations. Do this when some strings have been translated.
        emailTo = list(self.smtpFromAddr.partition('@'))
        emailTo.insert(1, '+zh_CN')
        emailTo = ''.join(emailTo)
        emailText = self._buildEmail(toAddr=emailTo)
        self._test(['HELO localhost',
                    'MAIL FROM: testing@localhost',
                    'RCPT TO: %s' % emailTo,
                    "DATA", emailText],
                   "250 Delivery in progress",
                   noisy=True)

    def test_MailFactory_DATA_get_bridges_QUIT(self):
        """Test sending 'DATA' with 'get bridges', then sending 'QUIT'."""
        emailText = self._buildEmail()
        self._test(['HELO localhost',
                    'MAIL FROM: testing@localhost',
                    'RCPT TO: %s' % self.smtpFromAddr,
                    "DATA", emailText,
                    "QUIT"],
                   "221 See you later",
                   noisy=True)


class EmailServerServiceTests(SMTPTestCaseMixin, unittest.TestCase):
    """Unittests for :func:`bridgedb.email.server.addServer`."""

    def setUp(self):
        """Create a server.MailContext and EmailBasedDistributor."""
        self.config = _createConfig()
        self.context = _createMailContext(self.config)
        self.smtpFromAddr = self.context.smtpFromAddr  # 'bridges@localhost'
        self.sched = Unscheduled()
        self.dist = self.context.distributor

    def tearDown(self):
        """Kill all connections with fire."""
        if self.transport:
            self.transport.loseConnection()
        super(EmailServerServiceTests, self).tearDown()
        # FIXME: this is definitely not how we're supposed to do this, but it
        # kills the DirtyReactorAggregateErrors.
        reactor.disconnectAll()
        reactor.runUntilCurrent()

    def test_addServer(self):
        """Call :func:`bridgedb.email.server.addServer` to test startup."""
        factory = server.addServer(self.config, self.dist, self.sched)
        factory.timeout = None
        factory.protocol.timeout = None  # Or else the reactor gets dirty

        self.proto = factory.buildProtocol(('127.0.0.1', 0))
        self.proto.setTimeout(None)
        # Set the transport's protocol, because
        # StringTransportWithDisconnection is a bit janky:
        self.transport.protocol = self.proto
        self.proto.makeConnection(self.transport)

        serverHost = socket.gethostname()
        self._test(['HELO %s' % serverHost,
                    'MAIL FROM: testing@%s' % serverHost,
                    'RCPT TO: %s' % self.smtpFromAddr,
                    "DATA", self._buildEmail(body="get transport obfs3")],
                   "250 Delivery in progress",
                   noisy=True)
