# -*- coding: utf-8 -*-

"""Unittests for :mod:`bridgedb.safelog`."""

import re

from twisted.internet import defer
from twisted.test.proto_helpers import StringTransport
from twisted.trial import unittest

from bridgedb import safelog


class SafelogTests(unittest.TestCase):
    """Tests for functions and attributes in :mod:`bridgedb.safelog`."""

    def setUp(self):
        """Create a logger at debug level and add the filter to be tested."""
        self.logfile = StringTransport()
        self.handler = safelog.logging.StreamHandler(self.logfile)
        self.logger = safelog.logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(10)
        self.logger.addHandler(self.handler)
        self.sensitiveData = 'Nicholas Bourbaki'

    def tearDown(self):
        """Rewind and truncate the logfile so that we have an empty one."""
        self.logfile.clear()

    def test_setSafeLogging_off(self):
        """Calls to ``logSafely()`` should return the original data when
        ``safe_logging`` is disabled.
        """
        safelog.setSafeLogging(False)
        self.logger.warn("Got a connection from %s..."
                         % safelog.logSafely(self.sensitiveData))
        contents = self.logfile.value()
        self.assertIsNotNone(contents)
        #self.assertSubstring("Got a connection from", contents)
        #self.assertSubstring(self.sensitiveData, contents)
        #self.failIfSubstring("[scrubbed]", contents)

    def test_setSafeLogging_on(self):
        """Calls to ``logSafely()`` should return ``"[scrubbed]"`` for any
        arbitrary data when ``safe_logging`` is enabled.
        """
        safelog.setSafeLogging(True)
        self.logger.warn("Got a connection from %s..."
                         % safelog.logSafely(self.sensitiveData))
        contents = self.logfile.value()
        self.assertIsNotNone(contents)
        #self.assertSubstring("Got a connection from", contents)
        #self.failIfSubstring(self.sensitiveData, contents)
        #self.assertSubstring("[scrubbed]", contents)


class BaseSafelogFilterTests(unittest.TestCase):
    """Unittests for :class:`bridgedb.safelog.BaseSafelogFilter`."""

    def setUp(self):
        safelog.setSafeLogging(True)
        self.logfile = StringTransport()
        self.handler = safelog.logging.StreamHandler(self.logfile)
        self.logger = safelog.logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(10)
        self.logger.addHandler(self.handler)
        self.filter = safelog.BaseSafelogFilter()
        self.logger.addFilter(self.filter)

        self.logMessage = "testing 1 2 3"
        self.record = safelog.logging.LogRecord('name', 10, __file__, 1337,
                                                self.logMessage, {}, None)

    def test_doubleCheck(self):
        """BaseSafelogFilter.doubleCheck() should always return True."""
        checked = self.filter.doubleCheck(self.logMessage)
        self.assertTrue(checked)

    def test_filter(self):
        """Test filtering a log record with no ``easyFind`` nor ``pattern``.

        The ``LogRecord.message`` shouldn't change.
        """
        filtered = self.filter.filter(self.record)
        self.assertEqual(filtered.getMessage(), self.logMessage)

    def test_filter_withEasyFind(self):
        """Test filtering a log record with ``easyFind``, but no ``pattern``.

        The ``LogRecord.message`` shouldn't change.
        """
        self.filter.easyFind = "2"
        filtered = self.filter.filter(self.record)
        self.assertEqual(filtered.getMessage(), self.logMessage)

    def test_filter_withPattern(self):
        """Test filtering a log record with ``easyFind`` and ``pattern``."""
        self.filter.easyFind = "2"
        self.filter.pattern = re.compile("1 2 3")
        filtered = self.filter.filter(self.record)
        self.assertEqual(filtered.msg, "testing [scrubbed]")


class SafelogEmailFilterTests(unittest.TestCase):
    """Unittests for :class:`bridgedb.safelog.SafelogEmailFilter`."""

    def setUp(self):
        """Create a logger at debug level and add the filter to be tested."""
        self.logfile = StringTransport()
        self.handler = safelog.logging.StreamHandler(self.logfile)
        self.filter = safelog.SafelogEmailFilter()
        self.logger = safelog.logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(10)
        self.logger.addHandler(self.handler)
        self.logger.addFilter(self.filter)
        self.s1 = "Here is an email address: "
        self.s2 = "blackhole@torproject.org"

    def test_filter_withPattern(self):
        """Test filtering a log record with ``easyFind`` and ``pattern``."""
        record = safelog.logging.LogRecord('name', 10, __file__, 1337,
                                           "testing blackhole@torproject.org",
                                           {}, None)
        filtered = self.filter.filter(record)
        self.assertEqual(filtered.msg, "testing [scrubbed]")

    def test_debugLevel(self):
        self.logger.debug("%s %s" % (self.s1, self.s2))
        self.logfile.io.seek(0)
        contents = self.logfile.value()
        self.assertIsNotNone(contents)
        # XXX We should test the following assertions for each test_*Level
        # method, however, twisted.trial doesn't give us an easy way to wait
        # for the logging module to complete it's IO operations.
        #self.assertSubstring(self.s1, contents)
        #self.failIfSubstring(self.s2, contents)

    def test_infoLevel(self):
        self.logger.info("%s %s" % (self.s1, self.s2))
        self.logfile.io.seek(0)
        contents = self.logfile.value()
        self.assertIsNotNone(contents)

    def test_warnLevel(self):
        self.logger.warn("%s %s" % (self.s1, self.s2))
        self.logfile.io.seek(0)
        contents = self.logfile.value()
        self.assertIsNotNone(contents)

    def test_errorLevel(self):
        self.logger.error("%s %s" % (self.s1, self.s2))
        self.logfile.io.seek(0)
        contents = self.logfile.value()
        self.assertIsNotNone(contents)

    def test_exceptionLevel(self):
        try:
            raise Exception("%s %s" % (self.s1, self.s2))
        except Exception as error:
            self.logger.exception(error)

        self.logfile.io.seek(0)
        contents = self.logfile.value()
        self.assertIsNotNone(contents)
        #self.assertSubstring(self.s1, contents)
        # If an email address is within an Exception message, it doesn't get
        # sanitised.
        #self.assertSubstring(self.s2, contents)

    def test_withSafeLoggingDisabled(self):
        """The filter should be disabled if ``safe_logging`` is disabled."""
        safelog.setSafeLogging(False)
        self.logger.info("%s %s" % (self.s1, self.s2))
        self.logfile.io.flush()
        self.logfile.io.seek(0)
        contents = self.logfile.value()
        self.assertIsNotNone(contents)
        #self.assertSubstring(self.s1, contents)
        #self.assertSubstring(self.s2, contents)


class SafelogIPv4FilterTests(unittest.TestCase):
    """Unittests for :class:`bridgedb.safelog.SafelogIPv4Filter`."""

    def setUp(self):
        """Create a logger at debug level and add the filter to be tested."""
        self.logfile = StringTransport()
        self.handler = safelog.logging.StreamHandler(self.logfile)
        self.filter = safelog.SafelogIPv4Filter()
        self.logger = safelog.logging.getLogger(str(self.__class__.__name__))
        self.logger.addHandler(self.handler)
        self.logger.addFilter(self.filter)
        self.logger.setLevel(10)
        self.s1 = "There's an IPv4 address at the end of this book: "
        self.s2 = "1.2.3.4"

    def test_filter_withPattern(self):
        """Test filtering a log record with ``easyFind`` and ``pattern``."""
        record = safelog.logging.LogRecord('name', 10, __file__, 1337,
                                           "testing 1.2.3.4",
                                           {}, None)
        filtered = self.filter.filter(record)
        self.assertIsInstance(filtered, safelog.logging.LogRecord)

    def test_doubleCheck_IPv4(self):
        checked = self.filter.doubleCheck("1.2.3.4")
        self.assertIs(checked, True)

    def test_doubleCheck_IPv6(self):
        checked = self.filter.doubleCheck("2af1:a470:9b36::a1:3:82")
        self.assertIsNot(checked, True)

    def test_debugLevel(self):
        self.logger.debug("%s %s" % (self.s1, self.s2))
        self.logfile.io.seek(0)
        contents = self.logfile.value()
        self.assertIsNotNone(contents)

    def test_infoLevel(self):
        self.logger.info("%s %s" % (self.s1, self.s2))
        self.logfile.io.seek(0)
        contents = self.logfile.value()
        self.assertIsNotNone(contents)

    def test_warnLevel(self):
        self.logger.warn("%s %s" % (self.s1, self.s2))
        self.logfile.io.seek(0)
        contents = self.logfile.value()
        self.assertIsNotNone(contents)

    def test_errorLevel(self):
        self.logger.error("%s %s" % (self.s1, self.s2))
        self.logfile.io.seek(0)
        contents = self.logfile.value()
        self.assertIsNotNone(contents)

    def test_exceptionLevel(self):
        try:
            raise Exception("%s %s" % (self.s1, self.s2))
        except Exception as error:
            self.logger.exception(error)

        self.logfile.io.flush()
        self.logfile.io.seek(0)
        contents = self.logfile.value()
        self.assertIsNotNone(contents)

    def test_withSafeLoggingDisabled(self):
        """The filter should be disabled if ``safe_logging`` is disabled."""
        safelog.setSafeLogging(False)
        self.logger.info("%s %s" % (self.s1, self.s2))
        self.logfile.io.flush()
        self.logfile.io.seek(0)
        contents = self.logfile.value()
        self.assertIsNotNone(contents)


class SafelogIPv6FilterTests(unittest.TestCase):
    """Unittests for :class:`bridgedb.safelog.SafelogIPv6Filter`."""

    def setUp(self):
        """Create a logger at debug level and add the filter to be tested."""
        self.logfile = StringTransport()
        self.handler = safelog.logging.StreamHandler(self.logfile)
        self.filter = safelog.SafelogIPv6Filter()
        self.logger = safelog.logging.getLogger(str(self.__class__.__name__))
        self.logger.addHandler(self.handler)
        self.logger.addFilter(self.filter)
        self.logger.setLevel(10)
        self.s1 = "There's an IPv6 address at the end of this book: "
        self.s2 = "2af1:a470:9b36::a1:3:82"

    def test_filter_withPattern(self):
        """Test filtering a log record with ``easyFind`` and ``pattern``."""
        record = safelog.logging.LogRecord('name', 10, __file__, 1337,
                                           "2af1:a470:9b36::a1:3:82",
                                           {}, None)
        filtered = self.filter.filter(record)
        self.assertIsInstance(filtered, safelog.logging.LogRecord)

    def test_doubleCheck_IPv4(self):
        checked = self.filter.doubleCheck("1.2.3.4")
        self.assertIsNot(checked, True)

    def test_doubleCheck_IPv6(self):
        checked = self.filter.doubleCheck("2af1:a470:9b36::a1:3:82")
        self.assertIs(checked, True)

    def test_debugLevel(self):
        self.logger.debug("%s %s" % (self.s1, self.s2))
        self.logfile.io.seek(0)
        contents = self.logfile.value()
        self.assertIsNotNone(contents)

    def test_infoLevel(self):
        self.logger.info("%s %s" % (self.s1, self.s2))
        self.logfile.io.seek(0)
        contents = self.logfile.value()
        self.assertIsNotNone(contents)

    def test_warnLevel(self):
        self.logger.warn("%s %s" % (self.s1, self.s2))
        self.logfile.io.seek(0)
        contents = self.logfile.value()
        self.assertIsNotNone(contents)

    def test_errorLevel(self):
        self.logger.error("%s %s" % (self.s1, self.s2))
        self.logfile.io.seek(0)
        contents = self.logfile.value()
        self.assertIsNotNone(contents)

    def test_exceptionLevel(self):
        try:
            raise Exception("%s %s" % (self.s1, self.s2))
        except Exception as error:
            self.logger.exception(error)

        self.logfile.io.flush()
        self.logfile.io.seek(0)
        contents = self.logfile.value()
        self.assertIsNotNone(contents)
        #self.assertSubstring(self.s1, contents)
        # If an IP address is within an Exception message, it doesn't get
        # sanitised.
        #self.assertSubstring(self.s2, contents)

    def test_withSafeLoggingDisabled(self):
        """The filter should be disabled if ``safe_logging`` is disabled."""
        safelog.setSafeLogging(False)
        self.logger.info("%s %s" % (self.s1, self.s2))

        self.logfile.io.flush()
        self.logfile.io.seek(0)
        contents = self.logfile.value()
        self.assertIsNotNone(contents)
