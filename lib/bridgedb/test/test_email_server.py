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
from bridgedb.Time import NoSchedule
from bridgedb.parse.addr import BadEmail
from bridgedb.persistent import Conf
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

    context = server.MailContext(config, distributor, NoSchedule())
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
        self.toAddress = clientAddress
        lines = [
            "From: %s" % clientAddress,
            "To: bridges@localhost",
            "Subject: testing",
            "",
            "get bridges",
        ]
        return lines

    def test_createResponseBody_noFrom(self):
        """A received email without a "From:" or "Sender:" header shouldn't
        receive a response.
        """
        lines = self._getIncomingLines()
        lines[0] = ""
        ret = server.createResponseBody(lines, self.ctx, self.toAddress)
        self.assertIsNone(ret)

    def test_createResponseBody_badAddress(self):
        """Don't respond to RFC2822 malformed source addresses."""
        lines = self._getIncomingLines("testing*.?\"@example.com")
        ret = server.createResponseBody(lines, self.ctx, self.toAddress)
        self.assertIsNone(ret)

    def test_createResponseBody_anotherBadAddress(self):
        """Don't respond to RFC2822 malformed source addresses."""
        lines = self._getIncomingLines("<>>@example.com")
        lines[0] = "From: Mallory %s" % self.toAddress
        ret = server.createResponseBody(lines, self.ctx, self.toAddress)
        self.assertIsNone(ret)

    def test_createResponseBody_invalidDomain(self):
        """Don't respond to RFC2822 malformed source addresses."""
        lines = self._getIncomingLines("testing@exa#mple.com")
        ret = server.createResponseBody(lines, self.ctx, self.toAddress)
        self.assertIsNone(ret)

    def test_createResponseBody_anotherInvalidDomain(self):
        """Don't respond to RFC2822 malformed source addresses."""
        lines = self._getIncomingLines("testing@exam+ple.com")
        ret = server.createResponseBody(lines, self.ctx, self.toAddress)
        self.assertIsNone(ret)

    def test_createResponseBody_DKIM_badDKIMheader(self):
        """An email with an 'X-DKIM-Authentication-Result:' header appended
        after the body should not receive a response.
        """
        lines = self._getIncomingLines("testing@gmail.com")
        lines.append("X-DKIM-Authentication-Result: ")
        ret = server.createResponseBody(lines, self.ctx, self.toAddress)
        self.assertIsNone(ret)

    def test_createResponseBody_DKIM(self):
        """An email with a good DKIM header should be responded to."""
        lines = self._getIncomingLines("testing@localhost")
        lines.insert(3, "X-DKIM-Authentication-Result: ")
        ret = server.createResponseBody(lines, self.ctx, self.toAddress)
        self.assertEqual(ret.find("no bridges currently"), -1)

    def test_createResponseBody_bridges_obfs3(self):
        """A request for 'transport obfs3' should receive a response."""
        lines = self._getIncomingLines("testing@localhost")
        lines[4] = "transport obfs3"
        ret = server.createResponseBody(lines, self.ctx, self.toAddress)
        self.assertEqual(ret.find("no bridges currently"), -1)

    def test_createResponseBody_bridges_obfsobfswebz(self):
        """We should only pay attention to the *last* in a crazy request."""
        lines = self._getIncomingLines("testing@localhost")
        lines[4] = "unblocked webz"
        lines.append("transport obfs2")
        lines.append("transport obfs3")
        ret = server.createResponseBody(lines, self.ctx, self.toAddress)
        self.assertNotEqual(ret.find("no bridges currently"), -1)

    def test_createResponseBody_bridges_obfsobfswebzipv6(self):
        """We should *still* only pay attention to the *last* request."""
        lines = self._getIncomingLines("testing@localhost")
        lines[4] = "transport obfs3"
        lines.append("unblocked webz")
        lines.append("ipv6")
        lines.append("transport obfs2")
        ret = server.createResponseBody(lines, self.ctx, self.toAddress)
        self.assertNotEqual(ret.find("no bridges currently"), -1)


class EmailReplyTests(unittest.TestCase):
    """Tests for ``EmailServer.replyToMail()``."""

    def setUp(self):
        """Create fake email, distributor, and associated context data."""
        # TODO: Add headers if we start validating them
        self.lines = ["From: %s@%s.com",
                      "To: bridges@example.net",
                      "Subject: testing",
                      "\n",
                      "get bridges"]
        self.ctx = _createMailContext()

    def test_replyToMail(self):
        self.skip = True
        raise unittest.SkipTest("We'll have to fake the EmailServer for this one,"\
                                " it requires a TCP connection to localhost.")

        def callback(reply):
            self.assertSubstring("Here are your bridges", reply)

        lines = copy.copy(self.lines)
        lines[0] = self.lines[0] % ("testing", "example")
        reply = EmailServer.replyToMail(lines, self.ctx)

        self.assertIsInstance(reply, defer.Deferred)

        reply.addCallback(callback)
        return reply


class EmailServerServiceTests(unittest.TestCase):
    def setUp(self):
        self.config = _createConfig()
        self.context = _createMailContext(self.config)
        self.distributor = self.context.distributor

    def test_addServer(self):
        self.skip = True
        raise unittest.SkipTest("Not finished yet")
        from twisted.internet import reactor
        server.addServer(self.config, self.distributor, NoSchedule)
