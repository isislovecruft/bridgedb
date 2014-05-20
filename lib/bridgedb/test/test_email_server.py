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
from twisted.test import proto_helpers
from twisted.trial import unittest


TEST_CONFIG_FILE = io.StringIO(unicode("""\
EMAIL_DIST = True
EMAIL_INCLUDE_FINGERPRINTS = True
EMAIL_GPG_SIGNING_ENABLED = True
EMAIL_GPG_SIGNING_KEY = 'TESTING.subkeys.sec'
EMAIL_DOMAIN_MAP = {
   'googlemail.com': 'gmail.com',
   'mail.google.com': 'gmail.com',
}
EMAIL_DOMAIN_RULES = {
   'gmail.com': ["ignore_dots", "dkim"],
   'example.com': [],
   'localhost': [],
}
EMAIL_DOMAINS = ["gmail.com", "example.com", "localhost"]
EMAIL_USERNAME = "bridges"
EMAIL_SMTP_HOST = "127.0.0.1"
EMAIL_SMTP_PORT = 25
EMAIL_SMTP_FROM_ADDR = "bridges@localhost"
EMAIL_N_BRIDGES_PER_ANSWER = 3
EMAIL_FROM_ADDR = "bridges@localhost"
EMAIL_BIND_IP = "127.0.0.1"
EMAIL_PORT = 5225
"""))


def _createConfig(configFile=TEST_CONFIG_FILE):
    configuration = {}
    TEST_CONFIG_FILE.seek(0)
    compiled = compile(configFile.read(), '<string>', 'exec')
    exec compiled in configuration
    config = Conf(**configuration)
    return config

def _createMailContext(config=None, distributor=None):
    if not config:
        config = _createConfig()

    if not distributor:
        distributor = DummyEmailDistributor(
            domainmap=config.EMAIL_DOMAIN_MAP,
            domainrules=config.EMAIL_DOMAIN_RULES)

    context = server.MailContext(config, distributor, Unscheduled())
    return context


class DummyEmailDistributor(object):
    """A mocked :class:`bridgedb.Dist.EmailBasedDistributor` which is used to
    test :class:`bridgedb.EmailServer`.
    """

    def __init__(self, key=None, domainmap=None, domainrules=None,
                 answerParameters=None):
        """None of the parameters are really used, ― they are just there to retain an
        identical method signature.
        """
        self.key = self.__class__.__name__
        self.domainmap = domainmap
        self.domainrules = domainrules
        self.answerParameters = answerParameters

    def getBridgesForEmail(self, emailaddress, epoch, N=1, parameters=None,
                           countryCode=None, bridgeFilterRules=None):
        return [DummyBridge() for _ in xrange(N)]

    def cleanDatabase(self):
        pass


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

    def test_generateResponse(self):
        response = server.generateResponse(self.fromAddr, self.clientAddr,
                                           self.body)
        self.assertIsInstance(response, server.MailResponse)

    def test_generateResponse_noSafelog(self):
        server.safelog.safe_logging = False
        response = server.generateResponse(self.fromAddr, self.clientAddr,
                                           self.body)
        self.assertIsInstance(response, server.MailResponse)

    def test_generateResponse_mailfile(self):
        response = server.generateResponse(self.fromAddr, self.clientAddr,
                                           self.body)
        self.assertIsInstance(response.mailfile, (io.BytesIO, io.StringIO))

    def test_generateResponse_withInReplyTo(self):
        response = server.generateResponse(self.fromAddr, self.clientAddr,
                                           self.body, messageID="NSA")
        contents = str(response.readContents()).replace('\x00', '')
        self.assertIsInstance(response.mailfile, (io.BytesIO, io.StringIO))
        self.assertSubstring("In-Reply-To: NSA", contents)

    def test_generateResponse_readContents(self):
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


class MailDeliveryTest(unittest.TestCase):
    """Unittests for :class:`email.server.MailDelivery`."""

    def setUp(self):
        self.config = _createConfig()
        self.context = _createMailContext(self.config)
        self.delivery = server.MailDelivery()
        self.helo = ('fubar.example.com', '127.0.0.1')
        self.origin = server.smtp.Address('user@example.com')
        self.users = [server.smtp.User('bridges', self.helo, None, self.origin),]

    def tets_MailDelivery(self):
        self.assertIsInstance(self.delivery, server.MailDelivery)

    def test_MailDelivery_setBridgeDBContext(self):
        self.delivery.setBridgeDBContext(self.context)

    def test_MailDelivery_receivedHeader(self):
        self.delivery.setBridgeDBContext(self.context)
        hdr = self.delivery.receivedHeader(self.helo, self.origin, self.users)
        self.assertTrue(hdr)
        self.assertSubstring("Received: from fubar.example.com", hdr)

    def test_MailDelivery_validateFrom(self):
        """A valid origin should be stored as ``MailDelivery.fromCanonical``."""
        self.delivery.setBridgeDBContext(self.context)
        self.delivery.validateFrom(self.helo, self.origin)
        self.assertEqual(self.delivery.fromCanonical, 'example.com')

    def test_MailDelivery_validateFrom_unsupportedDomain(self):
        """A domain not in our canon should raise a SMTPBadSender."""
        self.delivery.setBridgeDBContext(self.context)
        helo = ('yo.mama', '0.0.0.0')
        origin = server.smtp.Address('throwing.pickles@yo.mama')
        self.assertRaises(server.smtp.SMTPBadSender,
                          self.delivery.validateFrom, helo, origin)

    def test_MailDelivery_validateFrom_badOriginType(self):
        """A non t.m.smtp.Address origin should raise cause an Exception."""
        self.delivery.setBridgeDBContext(self.context)
        helo = ('yo.mama', '0.0.0.0')
        origin = 'throwing.pickles@yo.mama'
        self.delivery.validateFrom(helo, origin)

    def test_MailDelivery_validateTo(self):
        """Should return a callable that results in a MailMessage."""
        self.delivery.setBridgeDBContext(self.context)
        ret = self.delivery.validateTo(self.users[0])
        self.assertIsInstance(ret, types.FunctionType)

    def test_MailDelivery_validateTo_plusAddress(self):
        """Should return a callable that results in a MailMessage."""
        self.delivery.setBridgeDBContext(self.context)
        user = server.smtp.User('bridges+ar', self.helo, None, self.origin)
        ret = self.delivery.validateTo(user)
        self.assertIsInstance(ret, types.FunctionType)

    def test_MailDelivery_validateTo_badUsername(self):
        self.delivery.setBridgeDBContext(self.context)
        user = server.smtp.User('yo.mama', self.helo, None, self.origin)
        self.assertRaises(server.smtp.SMTPBadRcpt,
                          self.delivery.validateTo, user)


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

        self._test(['HELO localhost',
                    'MAIL FROM: testing@localhost',
                    'RCPT TO: %s' % self.smtpFromAddr,
                    "DATA", self._buildEmail(body="get transport obfs3")],
                   "250 Delivery in progress",
                   noisy=True)
