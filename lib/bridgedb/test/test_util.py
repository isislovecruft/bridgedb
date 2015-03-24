# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2014-2015, Isis Lovecruft
#             (c) 2007-2015, The Tor Project, Inc.
#             (c) 2007-2015, all entities within the AUTHORS file
# :license: see LICENSE for licensing information

"""Unittests for the :mod:`bridgedb.util` module."""

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import logging
import os

from twisted.mail.smtp import Address
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

    def test_getLogHandlers_disable_logfile(self):
        """util._getLogHandlers() should return ['console'] if stderr logging
        is disabled.
        """
        logHandlers = util._getLogHandlers(logToFile=False)
        self.assertIsInstance(logHandlers, list)
        self.assertEqual(len(logHandlers), 1)
        self.assertTrue('rotating' not in logHandlers)

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


class LevenshteinDistanceTests(unittest.TestCase):
    """Unittests for `bridgedb.util.levenshteinDistance."""

    def test_levenshteinDistance_blank_blank(self):
        """The Levenshtein Distance between '' and '' should be 0."""
        distance = util.levenshteinDistance('', '')
        self.assertEqual(distance, 0)

    def test_levenshteinDistance_cat_cat(self):
        """The Levenshtein Distance between 'cat' and 'cat' should be 0."""
        distance = util.levenshteinDistance('cat', 'cat')
        self.assertEqual(distance, 0)

    def test_levenshteinDistance_bat_cat(self):
        """The Levenshtein Distance between 'bat' and 'cat' should be 1."""
        distance = util.levenshteinDistance('bat', 'cat')
        self.assertEqual(distance, 1)

    def test_levenshteinDistance_bar_cat(self):
        """The Levenshtein Distance between 'bar' and 'cat' should be 2."""
        distance = util.levenshteinDistance('bar', 'cat')
        self.assertEqual(distance, 2)

    def test_levenshteinDistance_bridgedb_doge(self):
        """The Levenshtein Distance between 'bridgedb' and 'doge' should be 6."""
        distance = util.levenshteinDistance('bridgedb', 'doge')
        self.assertEqual(distance, 6)

    def test_levenshteinDistance_feidanchaoren0043_feidanchaoren0011(self):
        """The Levenshtein Distance between the usernames in
        'feidanchaoren0043@gmail.com' and 'feidanchaoren0011@gmail.com' should
        be less than an EMAIL_FUZZY_MATCH parameter.
        """
        email1 = Address('feidanchaoren0043@gmail.com')
        email2 = Address('feidanchaoren0011@gmail.com')
        # Fuzzy match if the Levenshtein Distance is less than or equal to:
        fuzzyMatch = 4
        distance = util.levenshteinDistance(email1.local, email2.local)
        self.assertLessEqual(distance, fuzzyMatch)


class JustifiedLogFormatterTests(unittest.TestCase):
    """Unittests for :class:`bridgedb.util.JustifiedLogFormatter`."""

    def setUp(self):
        # name, level, path, lineno, message, args, exc_info
        self.record = logging.LogRecord('name', logging.INFO, '/foo/bar/baz',
                                        12345, 'This is a message', None, None)

    def test_util_JustifiedLogFormatter(self):
        formatter = util.JustifiedLogFormatter()
        self.assertIsInstance(formatter, logging.Formatter)

    def test_util_JustifiedLogFormatter_logThreads(self):
        formatter = util.JustifiedLogFormatter(logThreads=True)
        self.assertIsInstance(formatter, logging.Formatter)

    def test_util_JustifiedLogFormatter_formatCallingFuncName(self):
        formatter = util.JustifiedLogFormatter()
        record = formatter._formatCallingFuncName(self.record)
        self.assertIsInstance(formatter, logging.Formatter)
        self.assertIsInstance(record, logging.LogRecord)

    def test_util_JustifiedLogFormatter_format(self):
        formatter = util.JustifiedLogFormatter()
        formatted = formatter.format(self.record)
        self.assertIsInstance(formatter, logging.Formatter)
        self.assertIsInstance(formatted, basestring)
        self.assertNotEqual(formatted, '')
        self.assertTrue('INFO' in formatted)
        self.assertTrue('This is a message' in formatted)
