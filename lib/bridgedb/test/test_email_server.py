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

import socket
import string
import types

from twisted.python import log
from twisted.internet import defer
from twisted.internet import reactor
from twisted.mail.smtp import IMessage
from twisted.mail.smtp import SMTPBadRcpt
from twisted.mail.smtp import SMTPBadSender
from twisted.mail.smtp import User
from twisted.mail.smtp import Address
from twisted.mail.smtp import rfc822
from twisted.test import proto_helpers
from twisted.trial import unittest

from zope.interface import implementedBy

from bridgedb.Dist import EmailBasedDistributor
from bridgedb.Dist import TooSoonEmail
from bridgedb.email import server
from bridgedb.parse.addr import BadEmail
from bridgedb.schedule import Unscheduled
from bridgedb.test.util import fileCheckDecorator
from bridgedb.test.util import TestCaseMixin
from bridgedb.test.email_helpers import _createConfig
from bridgedb.test.email_helpers import _createMailServerContext


class SMTPMessageTests(unittest.TestCase):
    """Unittests for :class:`bridgedb.email.server.SMTPMessage`."""

    def setUp(self):
        self.config = _createConfig()
        self.context = _createMailServerContext(self.config)
        self.message = server.SMTPMessage(self.context,
                                          canonicalFromSMTP='localhost')
        self.line = string.ascii_lowercase

    def tearDown(self):
        """Re-enable safelogging in between test runs."""
        server.safelog.setSafeLogging(True)

    def test_SMTPMessage_init(self):
        """Our ``message`` attribute should be a ``SMTPMessage`` object, and
        ``message.responder`` should be a
        :class:`bridgedb.email.autoresponder.SMTPAutoresponder`.
        """
        self.assertIsInstance(self.message, server.SMTPMessage)
        self.assertIsInstance(self.message.responder,
                              server.autoresponder.SMTPAutoresponder)

    def test_SMTPMessage_IMessage_interface(self):
        """``SMTPMessage`` should implement ``twisted.mail.smtp.IMessage``."""
        self.assertTrue(IMessage.implementedBy(server.SMTPMessage))

    def test_SMTPMessage_lineReceived_withSafelog(self):
        """Test sending a line of text to ``SMTPMessage.lineReceived`` with
        safelogging enabled.
        """
        server.safelog.setSafeLogging(True)
        self.message.lineReceived(self.line)
        self.assertEqual(self.message.nBytes, 26)
        self.assertTrue(self.line in self.message.lines)

    def test_SMTPMessage_lineReceived_withoutSafelog(self):
        """Test sending a line of text to ``SMTPMessage.lineReceived`` with
        safelogging disnabled.
        """
        server.safelog.setSafeLogging(False)
        for _ in range(3):
            self.message.lineReceived(self.line)
        self.assertEqual(self.message.nBytes, 3*26)
        self.assertTrue(self.line in self.message.lines)

    def test_SMTPMessage_eomReceived(self):
        """Calling ``oemReceived`` should return a deferred."""
        self.message.lineReceived(self.line)
        self.assertIsInstance(self.message.eomReceived(),
                              defer.Deferred)

    def test_SMTPMessage_getIncomingMessage(self):
        """``getIncomingMessage`` should return a ``rfc822.Message``."""
        self.message.lineReceived(self.line)
        self.assertIsInstance(self.message.getIncomingMessage(),
                              rfc822.Message)


class SMTPIncomingDeliveryTests(unittest.TestCase):
    """Unittests for :class:`email.server.SMTPIncomingDelivery`."""

    def setUp(self):
        """Set up our :class:`server.SMTPIncomingDelivery` instance, and reset the
        following ``TestCase`` attributes to ``None``:
            - ``helo``
            - ``proto``
            - ``origin``
            - ``user``
        """
        self.config = _createConfig()
        self.context = _createMailServerContext(self.config)
        self.delivery = server.SMTPIncomingDelivery()

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
        self.delivery.setContext(self.context)

    def _setUpRCPTTO(self, username=None, domain=None, ip=None):
        """Set up the parameters for emulating a connected client sending a
        SMTP 'RCPT TO:' command to us.

        The default is to emulate sending: ``RCPT TO: bridges@localhost``.
        """
        name = username if username is not None else self.config.EMAIL_USERNAME
        host = domain if domain is not None else 'localhost'
        addr = ip if ip is not None else '127.0.0.1'
        self._createUser(name, host, ip)
        self.delivery.setContext(self.context)

    def test_SMTPIncomingDelivery_init(self):
        """After calling :meth:`server.SMTPIncomingDelivery.__init__`, we should have a
        :class:`server.SMTPIncomingDelivery` object instance.
        """
        self.assertIsInstance(self.delivery, server.SMTPIncomingDelivery)

    def test_SMTPIncomingDelivery_setContext(self):
        """Calling :meth:`server.SMTPIncomingDelivery.setContext` should set
        the :ivar:`SMTPIncomingDelivery.context` attribute.

        The ``SMTPIncomingDelivery.context`` should be a :class:`server.MailServerContext`,
        and it should have relevant settings from the config file stored
        within it.
        """
        self.delivery.setContext(self.context)
        self.assertIsInstance(self.delivery.context, server.MailServerContext)
        self.assertEqual(self.delivery.context.smtpFromAddr,
                         self.config.EMAIL_SMTP_FROM_ADDR)

    def test_SMTPIncomingDelivery_receivedHeader(self):
        """The email resulting from a SMTPIncomingDelivery, the latter received from
        ``'client@example.com'`` should contain a header stating:
        ``'Received: from example.com'``.
        """
        self._createUser('client', 'example.com', '127.0.0.1')
        hdr = self.delivery.receivedHeader(self.helo, self.origin, [self.user,])
        self.assertSubstring("Received: from example.com", hdr)

    def test_SMTPIncomingDelivery_validateFrom(self):
        """A valid origin should be stored as ``SMTPIncomingDelivery.fromCanonical``."""
        self._setUpMAILFROM()
        self.delivery.validateFrom(self.helo, self.origin)
        self.assertEqual(self.delivery.fromCanonicalSMTP, 'example.com')

    def test_SMTPIncomingDelivery_validateFrom_unsupportedDomain(self):
        """A domain not in our canon should raise a SMTPBadSender."""
        self._setUpMAILFROM()
        origin = server.smtp.Address('throwing.pickles@yo.mama')
        self.assertRaises(SMTPBadSender,
                          self.delivery.validateFrom, self.helo, origin)

    def test_SMTPIncomingDelivery_validateFrom_origin_notAdressType(self):
        """A non ``twisted.mail.smtp.Address`` origin should raise an
        AttributeError exception.
        """
        self._setUpMAILFROM()
        origin = 'throwing.pickles@yo.mama'
        self.delivery.validateFrom(self.helo, origin)

    def test_SMTPIncomingDelivery_validateTo(self):
        """Should return a callable that results in a SMTPMessage."""
        self._setUpRCPTTO()
        validated = self.delivery.validateTo(self.user)
        self.assertIsInstance(validated, types.FunctionType)
        self.assertIsInstance(validated(), server.SMTPMessage)

    def test_SMTPIncomingDelivery_validateTo_plusAddress(self):
        """Should return a callable that results in a SMTPMessage."""
        self._setUpRCPTTO('bridges+ar')
        validated = self.delivery.validateTo(self.user)
        self.assertIsInstance(validated, types.FunctionType)
        self.assertIsInstance(validated(), server.SMTPMessage)

    def test_SMTPIncomingDelivery_validateTo_badUsername_plusAddress(self):
        """'givemebridges+zh_cn@...' should raise an SMTPBadRcpt exception."""
        self._setUpRCPTTO('givemebridges+zh_cn')
        self.assertRaises(SMTPBadRcpt, self.delivery.validateTo, self.user)

    def test_SMTPIncomingDelivery_validateTo_badUsername(self):
        """A :class:`server.SMTPIncomingDelivery` which sends a SMTP
        ``RCPT TO: yo.mama@localhost`` should raise a
        ``twisted.mail.smtp.SMTPBadRcpt`` exception.
        """
        self._setUpRCPTTO('yo.mama')
        self.assertRaises(SMTPBadRcpt, self.delivery.validateTo, self.user)

    def test_SMTPIncomingDelivery_validateTo_notOurDomain(self):
        """An SMTP ``RCPT TO: bridges@forealsi.es`` should raise an SMTPBadRcpt
        exception.
        """
        self._setUpRCPTTO('bridges', 'forealsi.es')
        self.assertRaises(SMTPBadRcpt, self.delivery.validateTo, self.user)

    def test_SMTPIncomingDelivery_validateTo_subdomain(self):
        """An SMTP ``RCPT TO: bridges@subdomain.localhost`` should be allowed.
        """
        self._setUpRCPTTO('bridges', 'subdomain.localhost')
        validated = self.delivery.validateTo(self.user)
        self.assertIsInstance(validated, types.FunctionType)
        self.assertIsInstance(validated(), server.SMTPMessage)


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
                factory = twisted.mail.smtp.SMTPIncomingServerFactory()
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

        Suitable for testing a :class:`bridgedb.email.server.SMTPIncomingServerFactory`.

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


class SMTPIncomingServerFactoryTests(SMTPTestCaseMixin, unittest.TestCase):
    """Unittests for :class:`bridgedb.email.server.SMTPIncomingServerFactory`."""

    def setUp(self):
        """Set up a localhost SMTPIncomingServerFactory handler incoming SMTP
        connections.
        """
        config = _createConfig()
        context = _createMailServerContext(config)
        factory = server.SMTPIncomingServerFactory()
        factory.setContext(context)
        factory.protocol.timeout = None  # Otherwise the reactor gets dirty

        self.smtpFromAddr = context.smtpFromAddr  # 'bridges@localhost'
        self.proto = factory.buildProtocol(('127.0.0.1', 0))
        self.transport = proto_helpers.StringTransportWithDisconnection()
        self.proto.setTimeout(None)
        # Set the protocol; StringTransportWithDisconnection is a bit janky:
        self.transport.protocol = self.proto
        self.proto.makeConnection(self.transport)

    def test_SMTPIncomingServerFactory_HELO_localhost(self):
        """Send 'HELO localhost' to the server's transport."""
        ip = self.transport.getPeer().host
        self._test(['HELO localhost'],
                   "Hello %s, nice to meet you" % ip)

    def test_SMTPIncomingServerFactory_MAIL_FROM_testing_at_localhost(self):
        """Send 'MAIL FROM: human@localhost'."""
        self._test(['HELO localhost',
                    'MAIL FROM: testing@localhost'],
                   "250 Sender address accepted")

    def test_SMTPIncomingServerFactory_MAIL_FROM_testing_at_gethostname(self):
        """Send 'MAIL FROM: human@hostname' for the local hostname."""
        hostname = socket.gethostname() or "computer"
        self._test(['HELO localhost',
                    'MAIL FROM: testing@%s' % hostname],
                   "250 Sender address accepted")

    def test_SMTPIncomingServerFactory_MAIL_FROM_testing_at_ipaddress(self):
        """Send 'MAIL FROM: human@ipaddr' for the loopback IP address."""
        hostname = 'localhost'
        self._test(['HELO localhost',
                    'MAIL FROM: testing@%s' % hostname],
                   "250 Sender address accepted")

    def test_SMTPIncomingServerFactory_RCPT_TO_context_smtpFromAddr(self):
        """Send 'RCPT TO:' with the context.smtpFromAddr."""
        self._test(['HELO localhost',
                    'MAIL FROM: testing@localhost',
                    'RCPT TO: %s' % self.smtpFromAddr],
                   "250 Recipient address accepted")

    def test_SMTPIncomingServerFactory_DATA_blank(self):
        """A DATA command with nothing after it should receive::
            '354 Continue'
        in response.
        """
        self._test(['HELO localhost',
                    'MAIL FROM: testing@localhost',
                    'RCPT TO: %s' % self.smtpFromAddr,
                    "DATA"],
                   "354 Continue")

    def test_SMTPIncomingServerFactory_DATA_get_help(self):
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

    def test_SMTPIncomingServerFactory_DATA_get_transport_obfs3(self):
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

    def test_SMTPIncomingServerFactory_DATA_To_bridges_plus_zh_CN(self):
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

    def test_SMTPIncomingServerFactory_DATA_get_bridges_QUIT(self):
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
        """Create a server.MailServerContext and EmailBasedDistributor."""
        self.config = _createConfig()
        self.context = _createMailServerContext(self.config)
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
