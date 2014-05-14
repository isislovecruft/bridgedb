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
import types

from bridgedb.Dist import EmailBasedDistributor
from bridgedb.email import server
from bridgedb.parse.addr import BadEmail
from bridgedb.persistent import Conf
from bridgedb.schedule import Unscheduled
from bridgedb.test.test_HTTPServer import DummyBridge
from bridgedb.test.util import fileCheckDecorator

from twisted.python import log
from twisted.internet import defer
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
}
EMAIL_DOMAINS = ["gmail.com", "example.com"]
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


class EmailServerServiceTests(unittest.TestCase):
    def setUp(self):
        self.config = _createConfig()
        self.context = _createMailContext(self.config)
        self.distributor = self.context.distributor

    def test_addServer(self):
        self.skip = True
        raise unittest.SkipTest("Not finished yet")
        from twisted.internet import reactor
        server.addServer(self.config, self.distributor, Unscheduled)
