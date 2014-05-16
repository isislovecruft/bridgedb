# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2014, Isis Lovecruft
#             (c) 2007-2014, The Tor Project, Inc.
#             (c) 2007-2014, all entities within the AUTHORS file
# :license: see LICENSE for licensing information

"""Unittests for the :mod:`bridgedb.util` module."""

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import os

from twisted.trial import unittest

from bridgedb import util


class MiscLoggingUtilTests(unittest.TestCase):
    """Unittests for miscellaneous logging functions in :mod:`bridgedb.util`."""

    def test_getLogHandlers(self):
        """util._getLogHandlers() should return ['rotating', 'console'] if
        both stderr and logfile logging are enabled.
        """
        logHandlers = util._getLogHandlers()
        self.assertIsInstance(logHandlers, list)
        self.assertEqual(len(logHandlers), 2)

    def test_getLogHandlers_disableStderr(self):
        """util._getLogHandlers() should return ['rotating'] if stderr logging
        is disabled.
        """
        logHandlers = util._getLogHandlers(logToStderr=False)
        self.assertIsInstance(logHandlers, list)
        self.assertEqual(len(logHandlers), 1)
        self.assertTrue('console' not in logHandlers)

    def test_getRotatingFileHandler(self):
        """_getRotatingFileHandler() should create a file with 0600
        permissions (os.ST_WRITE | os.ST_APPEND).
        """
        filename = str(self.id()) + '.log'
        logHandler = util._getRotatingFileHandler(filename)
        self.assertTrue(os.path.isfile(filename))
        self.assertEqual(os.stat_result(os.stat(filename)).st_mode, 33152)
        self.assertIsInstance(logHandler(),
                              util.logging.handlers.RotatingFileHandler)

    def test_configureLogging(self):
        """Configure logging should be callable without borking anything."""
        from bridgedb.persistent import Conf
        util.configureLogging(Conf())
        util.logging.info("BridgeDB's email address: bridges@torproject.org")
