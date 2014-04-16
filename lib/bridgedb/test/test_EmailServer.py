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
from bridgedb.test.util import fileCheckDecorator

from twisted.python import log
from twisted.internet import defer
from twisted.trial import unittest


TEST_CONFIG_FILE = io.StringIO(unicode("""\
EMAIL_DIST = True
EMAIL_GPG_SIGNING_ENABLED = True
EMAIL_GPG_SIGNING_KEY = 'TESTING.subkeys.sec'
EMAIL_DOMAIN_MAP = {}
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
        distributor = FakeDistributor('key', {}, {}, [])

    ctx = MailContext(config, distributor, NoSchedule())
    return ctx


class FakeDistributor(EmailBasedDistributor):
    def __init__(self, key, domainmap, domainrules, answerParameters=None,
                 bridges=None):
        super(FakeDistributor, self).__init__(key, domainmap, domainrules,
            answerParameters)
        if bridges:
            self.bridges = bridges
        else:
            self.bridges = []

    def getBridgesForEmail(self, emailaddr, epoch, N=1,
         parameters=None, countryCode=None, bridgeFilterRules=None):
        return self.bridges[:N]


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
                      "\n",
                      "get bridges"]
        self.distributor = FakeDistributor('key', {}, {}, [])
        self.ctx = _createMailContext(self.distributor)

    def test_getMailResponse_noFrom(self):
        """A received email without a "From:" or "Sender:" header shouldn't
        receive a response.
        """
        lines = self.lines
        lines[0] = ""
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self.assertIsInstance(ret, tuple)
        self.assertEqual(len(ret), 2)
        self.assertEqual(ret[0], None)
        self.assertEqual(ret[1], None)

    def test_getMailResponse_badAddress(self):
        lines = copy.copy(self.lines)
        lines[0] = self.lines[0] % ("testing*.?\"", "example")
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self.assertIsInstance(ret, tuple)
        self.assertEqual(len(ret), 2)
        self.assertEqual(ret[0], None)
        self.assertEqual(ret[1], None)

    def test_getMailResponse_anotherBadAddress(self):
        lines = copy.copy(self.lines)
        lines[0] = "From: Mallory %s@%s.com" % ("<>>", "example")
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self.assertIsInstance(ret, tuple)
        self.assertEqual(len(ret), 2)
        self.assertEqual(ret[0], None)
        self.assertEqual(ret[1], None)

    def test_getMailResponse_invalidDomain(self):
        lines = copy.copy(self.lines)
        lines[0] = self.lines[0] % ("testing", "exa#mple")
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self.assertIsInstance(ret, tuple)
        self.assertEqual(len(ret), 2)
        self.assertEqual(ret[0], None)
        self.assertEqual(ret[1], None)

    def test_getMailResponse_anotherInvalidDomain(self):
        lines = copy.copy(self.lines)
        lines[0] = self.lines[0] % ("testing", "exam+ple")
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self.assertIsInstance(ret, tuple)
        self.assertEqual(len(ret), 2)
        self.assertEqual(ret[0], None)
        self.assertEqual(ret[1], None)

    def test_getMailResponse_DKIM_badDKIMheader(self):
        """An email with an appended 'X-DKIM-Authentication-Result:' header should not
        receive a response.
        """
        lines = copy.copy(self.lines)
        lines[0] = self.lines[0] % ("testing", "gmail")
        lines.append("X-DKIM-Authentication-Result: ")
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self.assertIsInstance(ret, tuple)
        self.assertEqual(len(ret), 2)
        self.assertEqual(ret[0], None)
        self.assertEqual(ret[1], None)

    def test_getMailResponse_DKIM(self):
        lines = copy.copy(self.lines)
        lines[0] = self.lines[0] % ("testing", "example")
        lines.append("X-DKIM-Authentication-Result: ")
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self.assertIsInstance(ret, tuple)
        self.assertEqual(len(ret), 2)
        self.assertEqual(ret[0], "testing@example.com")
        self.assertIsInstance(ret[1], io.BytesIO)
        mail = ret[1].getvalue()
        self.assertNotEqual(mail.find("no bridges currently"), -1)

    def test_getMailResponse_bridges_obfs(self):
        """A request for 'transport obfs' should receive a response."""
        lines = copy.copy(self.lines)
        lines[0] = self.lines[0] % ("testing", "example")
        lines.append("transport obfs")
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self.assertIsInstance(ret, tuple)
        self.assertEqual(len(ret), 2)
        self.assertEqual(ret[0], "testing@example.com")
        self.assertIsInstance(ret[1], io.BytesIO)
        mail = ret[1].getvalue()
        self.assertNotEqual(mail.find("no bridges currently"), -1)

    def test_getMailResponse_bridges_obfsobfswebz(self):
        """We should only pay attention to the first in a crazy request."""
        lines = copy.copy(self.lines)
        lines[0] = self.lines[0] % ("testing", "example")
        lines.append("transport obfs")
        lines.append("transport obfs")
        lines.append("unblocked webz")
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self.assertIsInstance(ret, tuple)
        self.assertEqual(len(ret), 2)
        self.assertEqual(ret[0], "testing@example.com")
        self.assertIsInstance(ret[1], io.BytesIO)
        mail = ret[1].getvalue()
        self.assertNotEqual(mail.find("no bridges currently"), -1)

    def test_getMailResponse_bridges_obfsobfswebzipv6(self):
        """We should *still* only pay attention to the first request."""
        lines = copy.copy(self.lines)
        lines[0] = self.lines[0] % ("testing", "example")
        lines.append("transport obfs")
        lines.append("transport obfs")
        lines.append("unblocked webz")
        lines.append("ipv6")
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self.assertIsInstance(ret, tuple)
        self.assertEqual(len(ret), 2)
        self.assertEqual(ret[0], "testing@example.com")
        self.assertIsInstance(ret[1], io.BytesIO)
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
        self.distributor = FakeDistributor('key', {}, {}, [])
        self.ctx = _createMailContext(self.distributor)

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
        configuration = {}
        TEST_CONFIG_FILE.seek(0)
        compiled = compile(TEST_CONFIG_FILE.read(), '<string>', 'exec')
        exec compiled in configuration
        self.config = Conf(**configuration)

        # TODO: Add headers if we start validating them
        self.lines = ["From: %s@%s.com", "To: %s@example.net",
                      "Subject: testing", "\n", "get bridges"]
        self.distributor = FakeDistributor('key', {}, {}, [])
        self.ctx = MailContext(self.config, self.distributor, NoSchedule())

    def test_receiveMail(self):
        self.skip = True
        raise unittest.SkipTest("Not finished yet")
        from twisted.internet import reactor
        EmailServer.addSMTPServer(self.config, self.distributor, NoSchedule)
