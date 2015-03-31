# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2014-2015, Isis Lovecruft
#             (c) 2014-2015, The Tor Project, Inc.
# :license: see LICENSE for licensing information

"""Unittests for the :mod:`bridgedb.schedule` module."""

from __future__ import print_function

from twisted.trial import unittest

from bridgedb import schedule


class UnscheduledTests(unittest.TestCase):
    """Tests for :class:`bridgedb.scheduled.Unscheduled`."""

    def setUp(self):
        self.sched = schedule.Unscheduled()

    def test_Unscheduled_init(self):
        """The instance should be an instance of its class."""
        self.assertIsInstance(self.sched, schedule.Unscheduled)

    def test_Unscheduled_providesISchedule(self):
        """Unscheduled should implement the ISchedule interface."""
        schedule.ISchedule.namesAndDescriptions()
        self.assertTrue(schedule.ISchedule.providedBy(self.sched))

    def test_Unscheduled_intervalStart_noargs(self):
        time = self.sched.intervalStart()
        self.assertIsInstance(time, int)
        self.assertEquals(time, -62135596800)

    def test_Unscheduled_getInterval_is_constant(self):
        import time
        now = time.time()

        interval_default = self.sched.getInterval()
        self.assertIsInstance(interval_default, str)

        interval_zero = self.sched.getInterval(0)
        self.assertIsInstance(interval_zero, str)

        interval_now = self.sched.getInterval(now)
        self.assertIsInstance(interval_now, str)

        self.assertEquals(interval_default, interval_zero)
        self.assertEquals(interval_default, interval_now)

    def test_Unscheduled_nextIntervalStarts_noargs(self):
        time = self.sched.nextIntervalStarts()
        self.assertIsInstance(time, int)
        self.assertEquals(time, 253402300799)


class ScheduledIntervalTests(unittest.TestCase):
    """Tests for :class:`bridgedb.scheduled.ScheduledInterval`."""

    def setUp(self):
        import time
        self.now = time.time
        self.sched = schedule.ScheduledInterval

    def test_ScheduledInterval_providesISchedule(self):
        """ScheduledInterval should implement the ISchedule interface."""
        self.assertTrue(schedule.ISchedule.providedBy(self.sched(1, 'month')))

    def _check_init(self, sched):
        """The instance should be an instance of its class."""
        self.assertIsInstance(sched, schedule.ScheduledInterval)

    def test_ScheduledInterval_init_month(self):
        self._check_init(self.sched(1, 'month'))

    def test_ScheduledInterval_init_week(self):
        self._check_init(self.sched(2, 'week'))

    def test_ScheduledInterval_init_day(self):
        self._check_init(self.sched(5, 'days'))

    def test_ScheduledInterval_init_hour(self):
        self._check_init(self.sched(12, 'hours'))

    def test_ScheduledInterval_init_minute(self):
        self._check_init(self.sched(10, 'minute'))

    def test_ScheduledInterval_init_seconds(self):
        self._check_init(self.sched(30, 'seconds'))

    def test_ScheduledInterval_init_badIntervalPeriod(self):
        self.assertRaises(schedule.UnknownInterval,
                          self.sched, 2, 'decades')

    def test_ScheduledInterval_init_badIntervalCount(self):
        self.assertRaises(schedule.UnknownInterval,
                          self.sched, 'd20', 'minutes')

    def test_ScheduledInterval_init_negativeIntervalCount(self):
        sched = self.sched(-100000, 'days')
        self.assertEquals(sched.intervalCount, 1)
        self.assertEquals(sched.intervalPeriod, 'day')

    def test_ScheduledInterval_init_noargs(self):
        """Check that the defaults parameters function as expected."""
        sched = self.sched()
        self.assertEquals(sched.intervalCount, 1)
        self.assertEquals(sched.intervalPeriod, 'hour')

    def _check_intervalStart(self, count=30, period='second', variance=30):
        """Test the ScheduledInterval.intervalStart() method.

        :param int count: The number of **period**s within an interval.
        :param str period: The interval type for the period.
        :param int variance: The amount of variance (in seconds) to tolerate
            between the start of the interval containing now, and now.
        """
        now = int(self.now())
        sched = self.sched(count, period)
        time = sched.intervalStart(now)
        self.assertIsInstance(time, int)
        self.assertApproximates(now, time, variance)

    def test_ScheduledInterval_intervalStart_month(self):
        self._check_intervalStart(1, 'month', 31*24*60*60)

    def test_ScheduledInterval_intervalStart_week(self):
        self._check_intervalStart(2, 'week', 14*24*60*60)

    def test_ScheduledInterval_intervalStart_day(self):
        self._check_intervalStart(5, 'days', 5*24*60*60)

    def test_ScheduledInterval_intervalStart_hour(self):
        self._check_intervalStart(12, 'hours', 12*60*60)

    def test_ScheduledInterval_intervalStart_minute(self):
        self._check_intervalStart(10, 'minute', 10*60)

    def test_ScheduledInterval_intervalStart_seconds(self):
        self._check_intervalStart(30, 'seconds', 30)

    def test_ScheduledInterval_intervalStart_time_time(self):
        """Calling ScheduledInterval.intervalStart(time.time()) should only
        return ints, not floats.
        """
        import time

        timestamp = time.time()
        sched = self.sched(5, 'minutes')

        self.assertIsInstance(timestamp, float)
        self.assertIsInstance(sched.intervalStart(timestamp), int)

    def _check_getInterval(self, count=30, period='second', variance=30):
        """Test the ScheduledInterval.getInterval() method.

        :param int count: The number of **period**s within an interval.
        :param str period: The interval type for the period.
        :param int variance: The amount of variance (in seconds) to tolerate
            between the start of the interval containing now, and now.
        """
        now = int(self.now())
        sched = self.sched(count, period)
        ts = sched.getInterval(now)
        self.assertIsInstance(ts, str)
        secs = [int(x) for x in ts.replace('-', ' ').replace(':', ' ').split()]
        [secs.append(0) for _ in xrange(6-len(secs))]
        secs = schedule.calendar.timegm(secs)
        self.assertApproximates(now, secs, variance)

    def test_ScheduledInterval_getInterval_month(self):
        self._check_getInterval(2, 'month', 2*31*24*60*60)

    def test_ScheduledInterval_getInterval_week(self):
        self._check_getInterval(1, 'week', 7*24*60*60)

    def test_ScheduledInterval_getInterval_day(self):
        self._check_getInterval(4, 'days', 4*24*60*60)

    def test_ScheduledInterval_getInterval_hour(self):
        self._check_getInterval(23, 'hours', 23*60*60)

    def test_ScheduledInterval_getInterval_minute(self):
        self._check_getInterval(15, 'minutes', 15*60)

    def test_ScheduledInterval_getInterval_seconds(self):
        self._check_getInterval(10, 'seconds', 60)

    def _check_nextIntervalStarts(self, count=30, period='second', variance=30):
        """Test the ScheduledInterval.nextIntervalStarts() method.

        :param int count: The number of **period**s within an interval.
        :param str period: The interval type for the period.
        :param int variance: The amount of variance (in seconds) to tolerate
            between the start of the interval containing now, and now.
        """
        now = int(self.now())
        sched = self.sched(count, period)
        time = sched.nextIntervalStarts(now)
        self.assertIsInstance(time, int)
        # (now + variance - time) should be > variance
        self.assertApproximates(now + variance, time, variance)

    def test_ScheduledInterval_nextIntervalStarts_month(self):
        self._check_nextIntervalStarts(2, 'month', 2*31*24*60*60)

    def test_ScheduledInterval_nextIntervalStarts_week(self):
        self._check_nextIntervalStarts(1, 'week', 7*24*60*60)

    def test_ScheduledInterval_nextIntervalStarts_day(self):
        self._check_nextIntervalStarts(4, 'days', 4*24*60*60)

    def test_ScheduledInterval_nextIntervalStarts_hour(self):
        self._check_nextIntervalStarts(23, 'hours', 23*60*60)

    def test_ScheduledInterval_nextIntervalStarts_minute(self):
        self._check_nextIntervalStarts(15, 'minutes', 15*60)

    def test_ScheduledInterval_nextIntervalStarts_seconds(self):
        self._check_nextIntervalStarts(10, 'seconds', 10)
