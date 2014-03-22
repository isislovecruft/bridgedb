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

from io import StringIO
import StringIO.StringIO

from bridgedb import EmailServer
from bridgedb.Dist import BadEmail
from bridgedb.Dist import EmailBasedDistributor
from bridgedb.EmailServer import MailContext
from bridgedb.Time import NoSchedule
from bridgedb.persistent import Conf
from bridgedb.test.util import fileCheckDecorator
from twisted.python import log
from twisted.trial import unittest


TEST_CONFIG_FILE = StringIO(unicode("""\
EMAIL_DIST = True
EMAIL_GPG_SIGNING_ENABLED = True
EMAIL_GPG_SIGNING_KEY = 'TESTING.subkeys.sec'
"""))

class FakeDistributor(EmailBasedDistributor):
    def __init__(self, key, domainmap, domainrules, answerParameters=None,
                 bridges=None):
        super(Distributor, self).__init__(key, domainmap, domainrules,
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

class EmailCompositionTests(unittest.TestCase):
    """Tests for :func:`bridgedb.EmailServer.getMailResponse`."""

    def setup(self):
        """Create fake email and associated data"""
        # TODO: Add headers if we start validating them
        cfg = {'EMAIL_DOMAIN_MAP': {}}
        self.lines = ["From: %s@%s.com", "To: %s@example.net",
                      "Subject: testing", "\n", "get bridges"]
        distributor = FakeDistributor('key', {}, {}, [])
        self.ctx = MailContext(cfg, distributor, NoSchedule)

    def test_getMailResponseNoFrom(self):
        lines = self.lines
        lines[0] = ""
        lines[1] = lines[1] % "bridges"
        ret = EmailServer.getMailResponse(lines, None)
        self.assertIsInstance(ret, tuple)
        self.assertEqual(len(ret), 2)
        self.assertEqual(ret[0], None)
        self.assertEqual(ret[1], None)

    def test_getMailResponseBadAddress(self):
        lines = self.lines
        lines[0] = self.lines[0] % ("testing", "exa#mple")
        lines[0] = self.lines[0] % ("testing?", "example")
        lines[1] = self.lines[1] % "bridges"
        lines[2] = ""
        ret = EmailServer.getMailResponse(lines, None)
        self.assertIsInstance(ret, tuple)
        self.assertEqual(len(ret), 2)
        self.assertEqual(ret[0], None)
        self.assertEqual(ret[1], None)
        lines[0] = self.lines[0] % ("<>>", "example")
        ret = EmailServer.getMailResponse(lines, None)
        self.assertIsInstance(ret, tuple)
        self.assertEqual(len(ret), 2)
        self.assertEqual(ret[0], None)
        self.assertEqual(ret[1], None)

    def test_getMailResponseInvalidDomain(self):
        lines = self.lines
        lines[0] = self.lines[0] % ("testing", "exa#mple")
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self.assertIsInstance(ret, tuple)
        self.assertEqual(len(ret), 2)
        self.assertEqual(ret[0], None)
        self.assertEqual(ret[1], None)
        lines[0] = self.lines[0] % ("testing", "example")
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self.assertIsInstance(ret, tuple)
        self.assertEqual(len(ret), 2)
        self.assertEqual(ret[0], None)
        self.assertEqual(ret[1], None)

    def test_getMailResponseDKIM(self):
        cfg = {'EMAIL_DOMAIN_MAP': {},
               'EMAIL_DOMAIN_RULES': {
                   'gmail.com': ["ignore_dots", "dkim"],
                   'example.com': [],
                }
              }
        lines = self.lines
        lines[0] = self.lines[0] % ("testing", "gmail")
        lines.append("X-DKIM-Authentication-Result: ")
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self.assertIsInstance(ret, tuple)
        self.assertEqual(len(ret), 2)
        self.assertEqual(ret[0], None)
        self.assertEqual(ret[1], None)
        lines[0] = self.lines[0] % ("testing", "example")
        ret = EmailServer.getMailResponse(lines, self.ctx)
        self.assertIsInstance(ret, tuple)
        self.assertEqual(len(ret), 2)
        self.assertEqual(ret[0], "testing@example.com")
        self.assertIsInstance(ret[1], StringIO.StringIO)
        mail = ret[1].getvalue()
        self.assertNotEqual(mail.find("no bridges currently"), -1)
