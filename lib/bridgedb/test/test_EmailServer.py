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

"""Unittests for the :mod:`bridgedb.EmailServer` module."""

from __future__ import print_function

import os
import shutil

import io
import copy

from bridgedb import EmailServer
from bridgedb.Dist import EmailBasedDistributor
from bridgedb.EmailServer import MailContext
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

def _createMailContext(distributor=None):
    configuration = {}
    TEST_CONFIG_FILE.seek(0)
    compiled = compile(TEST_CONFIG_FILE.read(), '<string>', 'exec')
    exec compiled in configuration
    config = Conf(**configuration)

    if not distributor:
        distributor = DummyEmailDistributor(
            domainmap=config.EMAIL_DOMAIN_MAP,
            domainrules=config.EMAIL_DOMAIN_RULES)

    ctx = MailContext(config, distributor, NoSchedule())
    return ctx


class DummyEmailDistributor(object):
    """A mocked :class:`bridgedb.Dist.EmailBasedDistributor` which is used to
    test :class:`bridgedb.EmailServer`.
    """

    def __init__(self, key=None, domainmap=None, domainrules=None,
                 answerParameters=None):
        """None of the parameters are really used, except ``ctx`` ― they are
        just there to retain an identical method signature.
        """
        self.key = self.__class__.__name__
        self.domainmap = domainmap
        self.domainrules = domainrules
        self.answerParameters = answerParameters

    def getBridgesForEmail(self, emailaddress, epoch, N=1, parameters=None,
                           countryCode=None, bridgeFilterRules=None):
        """Needed because it's called in
        :meth:`WebResourceBridges.getBridgesForIP`.
        """
        return [DummyBridge() for _ in xrange(N)]


class EmailGnuPGTest(unittest.TestCase):
    """Tests for :func:`bridgedb.EmailServer.getGPGContext`."""

    timeout = 15

    @fileCheckDecorator
    def doCopyFile(self, src, dst, description=None):
        shutil.copy(src, dst)

    def removeRundir(self):
        if os.path.isdir(self.runDir):
            shutil.rmtree(self.runDir)

    def makeBadKey(self):
        keyfile = os.path.join(self.runDir, 'badkey.asc')
        with open(keyfile, 'wb') as badkey:
            badkey.write('NO PASARÁN, DEATH CAKES!')
            badkey.flush()
        self.setKey(keyfile)

    def setKey(self, keyfile=''):
        setattr(self.config, 'EMAIL_GPG_SIGNING_KEY', keyfile)

    def setUp(self):
        here          = os.getcwd()
        topDir        = here.rstrip('_trial_temp')
        self.runDir   = os.path.join(here, 'rundir')
        self.gpgFile  = os.path.join(topDir, 'gnupghome', 'TESTING.subkeys.sec')
        self.gpgMoved = os.path.join(here, 'TESTING.subkeys.sec')

        if not os.path.isdir(self.runDir):
            os.makedirs(self.runDir)

        configuration = {}
        TEST_CONFIG_FILE.seek(0)
        compiled = compile(TEST_CONFIG_FILE.read(), '<string>', 'exec')
        exec compiled in configuration
        self.config = Conf(**configuration)

        self.addCleanup(self.removeRundir)

    def test_getGPGContext_good_keyfile(self):
        """Test EmailServer.getGPGContext() with a good key filename.

        XXX: See #5463.
        """
        raise unittest.SkipTest(
            "See #5463 for why this test fails when it should pass")

        self.doCopyFile(self.gpgFile, self.gpgMoved, "GnuPG test keyfile")
        ctx = EmailServer.getGPGContext(self.config)
        self.assertIsInstance(ctx, EmailServer.gpgme.Context)

    def test_getGPGContext_missing_keyfile(self):
        """Test EmailServer.getGPGContext() with a missing key filename."""
        self.setKey('missing-keyfile.asc')
        ctx = EmailServer.getGPGContext(self.config)
        self.assertTrue(ctx is None)

    def test_getGPGContext_bad_keyfile(self):
        """Test EmailServer.getGPGContext() with a missing key filename."""
        self.makeBadKey()
        ctx = EmailServer.getGPGContext(self.config)
        self.assertTrue(ctx is None)


class EmailResponseTests(unittest.TestCase):
    """Tests for :func:`bridgedb.EmailServer.getMailResponse`."""

    def setUp(self):
        """Create fake email, distributor, and associated context data."""
        # TODO: Add headers if we start validating them
        self.lines = ["From: %s@%s.com",
                      "To: bridges@example.net",
                      "Subject: testing",
                      "",
                      "get bridges"]
        self.ctx = _createMailContext()

    def _isTwoTupleOfNone(self, reply):
        """Check that a return value is ``(None, None)``."""
        self.assertIsInstance(reply, tuple)
        self.assertEqual(len(reply), 2)
        self.assertEqual(reply[0], None)
        self.assertEqual(reply[1], None)

    def _isTwoTupleOfAddrAndClass(self, reply, address="testing@example.com",
                                  klass=io.StringIO):
        self.assertIsInstance(reply, tuple)
        self.assertEqual(len(reply), 2)
        self.assertEqual(reply[0], address)
        self.assertIsInstance(reply[1], klass)

    def test_getMailResponse_noFrom(self):
        """A received email without a "From:" or "Sender:" header shouldn't
        receive a response.
        """
        lines = self.lines
        lines[0] = ""
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self._isTwoTupleOfNone(ret)

    def test_getMailResponse_badAddress(self):
        """Don't respond to RFC2822 malformed source addresses."""
        lines = copy.copy(self.lines)
        lines[0] = self.lines[0] % ("testing*.?\"", "example")
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self._isTwoTupleOfNone(ret)

    def test_getMailResponse_anotherBadAddress(self):
        """Don't respond to RFC2822 malformed source addresses."""
        lines = copy.copy(self.lines)
        lines[0] = "From: Mallory %s@%s.com" % ("<>>", "example")
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self._isTwoTupleOfNone(ret)

    def test_getMailResponse_invalidDomain(self):
        """Don't respond to RFC2822 malformed source addresses."""
        lines = copy.copy(self.lines)
        lines[0] = self.lines[0] % ("testing", "exa#mple")
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self._isTwoTupleOfNone(ret)

    def test_getMailResponse_anotherInvalidDomain(self):
        """Don't respond to RFC2822 malformed source addresses."""
        lines = copy.copy(self.lines)
        lines[0] = self.lines[0] % ("testing", "exam+ple")
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self._isTwoTupleOfNone(ret)

    def test_getMailResponse_DKIM_badDKIMheader(self):
        """An email with an 'X-DKIM-Authentication-Result:' header appended
        after the body should not receive a response.
        """
        lines = copy.copy(self.lines)
        lines[0] = self.lines[0] % ("testing", "gmail")
        lines.append("X-DKIM-Authentication-Result: ")
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self._isTwoTupleOfNone(ret)

    def test_getMailResponse_DKIM(self):
        """An email with a good DKIM header should be responded to."""
        lines = copy.copy(self.lines)
        lines[0] = self.lines[0] % ("testing", "example")
        lines.append("X-DKIM-Authentication-Result: ")
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self._isTwoTupleOfAddrAndClass(ret)
        mail = ret[1].getvalue()
        self.assertNotEqual(mail.find("no bridges currently"), -1)

    def test_getMailResponse_bridges_obfs3(self):
        """A request for 'transport obfs3' should receive a response."""
        lines = copy.copy(self.lines)
        lines[0] = self.lines[0] % ("testing", "example")
        lines.append("transport obfs")
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self._isTwoTupleOfAddrAndClass(ret)
        mail = ret[1].getvalue()
        self.assertNotEqual(mail.find("no bridges currently"), -1)

    def test_getMailResponse_bridges_obfsobfswebz(self):
        """We should only pay attention to the *last* in a crazy request."""
        lines = copy.copy(self.lines)
        lines[0] = self.lines[0] % ("testing", "example")
        lines.append("transport obfs")
        lines.append("transport obfs")
        lines.append("unblocked webz")
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self._isTwoTupleOfAddrAndClass(ret)
        mail = ret[1].getvalue()
        self.assertNotEqual(mail.find("no bridges currently"), -1)

    def test_getMailResponse_bridges_obfsobfswebzipv6(self):
        """We should *still* only pay attention to the *last* request."""
        lines = copy.copy(self.lines)
        lines[0] = self.lines[0] % ("testing", "example")
        lines.append("transport obfs")
        lines.append("transport obfs")
        lines.append("unblocked webz")
        lines.append("ipv6")
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self._isTwoTupleOfAddrAndClass(ret)
        mail = ret[1].getvalue()
        self.assertNotEqual(mail.find("no bridges currently"), -1)


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
        # TODO: Add headers if we start validating them
        self.lines = ["From: %s@%s.com", "To: %s@example.net",
                      "Subject: testing", "\n", "get bridges"]
        self.distributor = DummyEmailDistributor('key', {}, {}, [])
        self.ctx = _createMailContext(self.distributor)

    def test_receiveMail(self):
        self.skip = True
        raise unittest.SkipTest("Not finished yet")
        from twisted.internet import reactor
        EmailServer.addSMTPServer(self.ctx.cfg, self.distributor, NoSchedule)
