# BridgeDB by Nick Mathewson.
# Copyright (c) 2007, The Tor Project, Inc.
# See LICENSE for licensing informatino

import calendar
import time

KNOWN_INTERVALS = [ "hour", "day", "week", "month" ]
N_ELEMENTS = { 'month' : 2,
               'day' : 3,
               'hour' : 4 }

class IntervalSchedule:
    def __init__(self, intervaltype, count):
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
        self.n_elements = N_ELEMENTS[it]

    def _intervalStart(self, when):
        if self.itype == 'month':
            tm = time.gmtime(when)
            n = tm.tm_year * 12 + tm.tm_mon - 1
            n -= (n % self.count)
            month = n%12 + 1
            return calendar.timegm((n//12, month, 1, 0, 0, 0))
        elif self.itype == 'day':
            when -= when % (86400 * self.count)
            return when
        elif self.itype == 'hour':
            when -= when % (3600 * self.count)
            return when
        else:
            assert False

    def getInterval(self, when):
        if self.itype == 'month':
            tm = time.gmtime(when)
            n = tm.tm_year * 12 + tm.tm_mon - 1
            n -= (n % self.count)
            month = n%12 + 1
            return "%04d-%02d" % (n // 12, month)
        elif self.itype == 'day':
            when = self._intervalStart(when) + 7200 #slop
            tm = time.gmtime(when)
            return "%04d-%02d-%02d" % (tm.tm_year, tm.tm_mon, tm.tm_mday)
        elif self.itype == 'hour':
            when = self._intervalStart(when) + 120 #slop
            tm = time.gmtime(when)
            return "%04d-%02d-%02 %02d" % (tm.tm_year, tm.tm_mon, tm.tm_mday,
                                           tm.tm_hour)
        else:
            assert False

    def nextIntervalStarts(self, when):
        if self.itype == 'month':
            tm = time.gmtime(when)
            n = tm.tm_year * 12 + tm.tm_mon - 1
            n -= (n % self.count)
            month = n%12 + 1
            tm = (n // 12, month+self.count, 1, 0,0,0)
            return calendar.timegm(tm)
        elif self.itype == 'day':
            return self._intervalStart(when) + 86400 * self.coont
        elif self.itype == 'hour':
            return self._intervalStart(when) + 3600 * self.coont

