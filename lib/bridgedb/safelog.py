# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_safelog -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2013-2015, Isis Lovecruft
#             (c) 2007-2015, The Tor Project, Inc.
# :license: 3-Clause BSD, see LICENSE for licensing information

"""Filters for log sanitisation.

The ``Safelog*Filter`` classes within this module can be instantiated and
adding to any :class:`logging.Handler`, in order to transparently filter
substrings within log messages which match the given ``pattern``. Matching
substrings may be optionally additionally validated by implementing the
:meth:`~BaseSafelogFilter.doubleCheck` method before they are finally replaced
with the ``replacement`` string. For example::

    >>> import io
    >>> import logging
    >>> from bridgedb import safelog
    >>> handler = logging.StreamHandler(io.BytesIO())
    >>> logger = logging.getLogger()
    >>> logger.addHandler(handler)
    >>> logger.addFilter(safelog.SafelogEmailFilter())
    >>> logger.info("Sent response email to: blackhole@torproject.org")

..

Module Overview:
~~~~~~~~~~~~~~~~
::
 safelog
  |
  |_setSafeLogging - Enable or disable safelogging globally.
  |_logSafely - Utility for manually sanitising a portion of a log message
  |
  |_BaseSafelogFilter - Base class for log message sanitisation filters
     |   |_doubleCheck - Optional stricter validation on matching substrings
     |   |_filter - Determine if some part of a log message should be filtered
     |
     |_SafelogEmailFilter - Filter for removing email addresses from logs
     |_SafelogIPv6Filter - Filter for removing IPv4 addresses from logs
     |_SafelogIPv6Filter - Filter for removing IPv6 addresses from logs
::
"""

import functools
import logging
import re

from bridgedb.parse import addr


safe_logging = True


def setSafeLogging(safe):
    """Enable or disable automatic filtering of log messages.

    :param bool safe: If ``True``, filter email and IP addresses from log
        messages automagically.
    """
    global safe_logging
    safe_logging = safe

def logSafely(string):
    """Utility for manually sanitising a portion of a log message.

    :param str string: If ``SAFELOGGING`` is enabled, sanitise this **string**
        by replacing it with ``"[scrubbed]"``. Otherwise, return the
        **string** unchanged.
    :rtype: str
    :returns: ``"[scrubbed]"`` or the original string.
    """
    if safe_logging:
        return "[scrubbed]"
    return string


class BaseSafelogFilter(logging.Filter):
    """Base class for creating log message sanitisation filters.

    A :class:`BaseSafelogFilter` uses a compiled regex :cvar:`pattern` to
    match particular items of data in log messages which should be sanitised
    (if ``SAFELOGGING`` is enabled in :file:`bridgedb.conf`).

    .. note:: The ``pattern`` is used only for string *matching* purposes, and
        *not* for validation. In other words, a ``pattern`` which matches email
        addresses should simply match something which appears to be an email
        address, even though that matching string might not technically be a
        valid email address vis-á-vis :rfc:`5321`.

    In addition, a ``BaseSafelogFilter`` uses a :cvar:`easyFind`, which is
    simply a string or character to search for before running checking against
    the regular expression, to attempt to avoid regexing *everything* which
    passes through the logger.

    :cvar pattern: A compiled regular expression, whose matches will be
        scrubbed from log messages and replaced with :cvar:`replacement`.
    :cvar easyFind: A simpler string to search for before regex matching.
    :cvar replacement: The string to replace ``pattern`` matches
        with. (default: ``"[scrubbed]"``)
    """
    pattern = re.compile("FILTERME")
    easyFind = "FILTERME"
    replacement = "[scrubbed]"

    def doubleCheck(self, match):
        """Subclasses should override this function to implement any additional
        substring filtering to decrease the false positive rate, i.e. any
        additional filtering or validation which is *more* costly than
        checking against the regular expression, :cvar:`pattern`.

        To use only the :cvar:`pattern` matching in :meth:`filter`, and not
        use this method, simply do::

            return True

        :param str match: Some portion of the :ivar:`logging.LogRecord.msg`
            string which has already passed the checks in :meth:`filter`, for
            which additional validation/checking is required.
        :rtype: bool
        :returns: ``True`` if the additional validation passes (in other
            words, the **match** *should* be filtered), and ``None`` or
            ``False`` otherwise.
        """
        return True

    def filter(self, record):
        """Filter a log record.

        The log **record** is filtered, and thus sanitised by replacing
        matching substrings with the :cvar:`replacement` string, if the
        following checks pass:

            0. ``SAFELOGGING`` is currently enabled.
            1. The ``record.msg`` string contains :cvar:`easyFind`.
            2. The ``record.msg`` matches the regular expression,
               :cvar:`pattern`.

        :type record: :class:`logging.LogRecord`
        :param record: Basically, anything passed to :func:`logging.log`.
        """
        if safe_logging:
            msg = str(record.msg)
            if msg.find(self.easyFind) > 0:
                matches = self.pattern.findall(msg)
                for match in matches:
                    if self.doubleCheck(match):
                        msg = msg.replace(match, self.replacement)
            record.msg = msg
        return record


class SafelogEmailFilter(BaseSafelogFilter):
    """A log filter which removes email addresses from log messages."""

    pattern = re.compile(
        "([a-zA-Z0-9]+[.+a-zA-Z0-9]*[@]{1}[a-zA-Z0-9]+[.-a-zA-Z0-9]*[.]{1}[a-zA-Z]+)")
    easyFind = "@"

    @functools.wraps(BaseSafelogFilter.filter)
    def filter(self, record):
        return BaseSafelogFilter.filter(self, record)


class SafelogIPv4Filter(BaseSafelogFilter):
    """A log filter which removes IPv4 addresses from log messages."""

    pattern = re.compile("(?:\d{1,3}\.?){4}")
    easyFind = "."

    def doubleCheck(self, match):
        """Additional check to ensure that **match** is an IPv4 address."""
        if addr.isIPv4(match):
            return True

    @functools.wraps(BaseSafelogFilter.filter)
    def filter(self, record):
        return BaseSafelogFilter.filter(self, record)


class SafelogIPv6Filter(BaseSafelogFilter):
    """A log filter which removes IPv6 addresses from log messages."""

    pattern = re.compile("([:]?[a-fA-F0-9:]+[:]+[a-fA-F0-9:]+){1,8}")
    easyFind = ":"

    def doubleCheck(self, match):
        """Additional check to ensure that **match** is an IPv6 address."""
        if addr.isIPv6(match):
            return True

    @functools.wraps(BaseSafelogFilter.filter)
    def filter(self, record):
        return BaseSafelogFilter.filter(self, record)
