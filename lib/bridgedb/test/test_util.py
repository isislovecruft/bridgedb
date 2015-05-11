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


class CacheTests(unittest.TestCase):
    """Unittests for :class:`bridgedb.util.Cache`."""

    def setUp(self):
        self.cache = util.Cache(3)

        self.cache[1] = 1
        self.cache[2] = 2
        self.cache[3] = 3

    def test_Cache_lru(self):
        """Cache.lru should be the least recently used item."""
        self.assertEqual(self.cache.lru.value, 1)

    def test_Cache_mru(self):
        """Cache.mru should be the most recently used item."""
        self.assertEqual(self.cache.mru.value, 3)

    def test_Cache_size_getter(self):
        """Cache.size should return the current size of the cache."""
        self.assertEqual(self.cache.size, 3)

    def test_Cache_size_setter(self):
        """Cache.size = 5 should set the current size of the cache to 5."""
        self.cache.size = 5
        self.assertEqual(self.cache.size, 5)

    def test_Cache_size_setter_float(self):
        """Cache.size = 5.0 should raise a TypeError."""
        self.assertRaises(TypeError, setattr, self.cache, 'size', 5.0)

    def test_Cache_delitem(self):
        """del Cache[3] should remove that item from the cache."""
        del self.cache[3]
        self.assertEqual(self.cache.mru.value, 2)

    def test_Cache_delitem_nonexistent(self):
        """del Cache[4] should raise a KeyError."""
        self.assertRaises(KeyError, self.cache.__delitem__, 4)

    def test_Cache_getitem(self):
        """Accessing Cache[1] should update the mru and lru."""
        self.cache[1]
        self.assertEqual(self.cache.mru.value, 1)
        self.assertEqual(self.cache.lru.value, 2)

    def test_Cache_getitem_nonexistent(self):
        """Accessing Cache[4] should raise a KeyError."""
        self.assertRaises(KeyError, self.cache.__getitem__, 4)

    def test_Cache_iter(self):
        """iter(Cache) should iterate over the item keys in the cache."""
        i = iter(self.cache)

        self.assertEqual(i.next(), 3)
        self.assertEqual(i.next(), 2)
        self.assertEqual(i.next(), 1)
        self.assertRaises(StopIteration, i.next)

        # The mru order shouldn't have been updated by the iteration:
        self.assertEqual(self.cache.mru.value, 3)

    def test_Cache_clear(self):
        """Cache.clear() should get rid of all items in the cache."""
        self.cache.clear()
        self.assertRaises(KeyError, self.cache.__getitem__, 1)
        self.assertRaises(KeyError, self.cache.__getitem__, 2)
        self.assertRaises(KeyError, self.cache.__getitem__, 3)

    def test_Cache_items(self):
        """Cache.items() should return a list of all items in the cache."""
        items = self.cache.items()
        self.assertIsInstance(items, list)
        self.assertEqual(len(items), 3)

    def test_Cache_keys(self):
        """Cache.keys() should return a list of all item keys in the cache."""
        keys = self.cache.keys()
        self.assertIsInstance(keys, list)
        self.assertEqual(len(keys), 3)
        self.assertItemsEqual(keys, [1, 2, 3])

    def test_Cache_values(self):
        """Cache.values() should return a list of all item values in the cache."""
        values = self.cache.values()
        self.assertIsInstance(values, list)
        self.assertEqual(len(values), 3)
        self.assertItemsEqual(values, [1, 2, 3])

    def test_Cache_shrink(self):
        """Cache.shrink(1) should remove the LRU item."""
        self.cache.shrink(1)
        self.assertEquals(len(self.cache), 2)
        self.assertEquals(self.cache.lru.value, 2)
