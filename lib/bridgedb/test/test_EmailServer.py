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

from bridgedb import EmailServer
from bridgedb.persistent import Conf
from bridgedb.test.util import fileCheckDecorator
from twisted.python import log
from twisted.trial import unittest


TEST_CONFIG_FILE = StringIO(unicode("""\
EMAIL_DIST = True
EMAIL_GPG_SIGNING_ENABLED = True
EMAIL_GPG_SIGNING_KEY = 'TESTING.subkeys.sec'
"""))


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
        os.makedirs(self.runDir)

        configuration = {}
        TEST_CONFIG_FILE.seek(0)
        compiled = compile(TEST_CONFIG_FILE.read(), '<string>', 'exec')
        exec compiled in configuration
        self.config = Conf(**configuration)

        self.addCleanup(self.removeRundir)

    def test_getGPGContext_good_keyfile(self):
        """Test EmailServer.getGPGContext() with a good key filename."""
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
