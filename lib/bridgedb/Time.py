# BridgeDB by Nick Mathewson.
# Copyright (c) 2007-2009, The Tor Project, Inc.
# See LICENSE for licensing information

"""
This module implements functions for dividing time into chunks.
"""

import calendar
import time

KNOWN_INTERVALS = [ "hour", "day", "week", "month" ]

class Schedule:
    def intervalStart(self, when):
        raise NotImplementedError
    def getInterval(self, when):
        raise NotImplementedError
    def nextIntervalStarts(self, when):
        raise NotImplementedError

class IntervalSchedule(Schedule):
    """An IntervalSchedule splits time into somewhat natural periods,
       based on hours, days, weeks, or months.
    """
    ## Fields:
    ##  itype -- one of "month", "day", "hour".
    ##  count -- how many of the units in itype belong to each period.
    def __init__(self, intervaltype, count):
        """Create a new IntervalSchedule.
            intervaltype -- one of month, week, day, hour.
            count -- how many of the units in intervaltype belong to each
                     period.
        """
        it = intervaltype.lower()
        if it.endswith("s"): it = it[:-1]
        if it not in KNOWN_INTERVALS:
            raise TypeError("What's a %s?"%it)
        assert count > 0
        if it == 'week':
            it = 'day'
            count *= 7
        self.itype = it
        self.count = count

    def intervalStart(self, when):
        """Return the time (as an int) of the start of the interval containing
           'when'."""
        if self.itype == 'month':
            # For months, we always start at the beginning of the month.
            tm = time.gmtime(when)
            n = tm.tm_year * 12 + tm.tm_mon - 1
            n -= (n % self.count)
            month = n%12 + 1
            return calendar.timegm((n//12, month, 1, 0, 0, 0))
        elif self.itype == 'day':
            # For days, we start at the beginning of a day.
            when -= when % (86400 * self.count)
            return when
        elif self.itype == 'hour':
            # For hours, we start at the beginning of an hour.
            when -= when % (3600 * self.count)
            return when
        else:
            assert False

    def getInterval(self, when):
        """Return a string representing the interval that contains
           the time 'when'.

        >>> import calendar
        >>> from bridgedb.Time import IntervalSchedule
        >>> t = calendar.timegm((2007, 12, 12, 0, 0, 0))
        >>> I = IntervalSchedule('month', 1)
        >>> I.getInterval(t)
        '2007-12'
        """
        if self.itype == 'month':
            tm = time.gmtime(when)
            n = tm.tm_year * 12 + tm.tm_mon - 1
            n -= (n % self.count)
            month = n%12 + 1
            return "%04d-%02d" % (n // 12, month)
        elif self.itype == 'day':
            when = self.intervalStart(when) + 7200 #slop
            tm = time.gmtime(when)
            return "%04d-%02d-%02d" % (tm.tm_year, tm.tm_mon, tm.tm_mday)
        elif self.itype == 'hour':
            when = self.intervalStart(when) + 120 #slop
            tm = time.gmtime(when)
            return "%04d-%02d-%02d %02d" % (tm.tm_year, tm.tm_mon, tm.tm_mday,
                                            tm.tm_hour)
        else:
            assert False

    def nextIntervalStarts(self, when):
        """Return the start time of the interval starting _after_ when."""
        if self.itype == 'month':
            tm = time.gmtime(when)
            n = tm.tm_year * 12 + tm.tm_mon - 1
            n -= (n % self.count)
            month = n%12 + 1
            tm = (n // 12, month+self.count, 1, 0,0,0)
            return calendar.timegm(tm)
        elif self.itype == 'day':
            return self.intervalStart(when) + 86400 * self.count
        elif self.itype == 'hour':
            return self.intervalStart(when) + 3600 * self.count

class NoSchedule(Schedule):
    """A stub-implementation of Schedule that has only one period for
       all time."""
    def __init__(self):
        pass
    def intervalStart(self, when):
        return 0
    def getInterval(self, when):
        return "1970"
    def nextIntervalStarts(self, when):
        return 2147483647L # INT32_MAX

