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
        self.assertTrue(schedule.ISchedule.providedBy(self.sched('month', 1)))

    def _check_init(self, sched):
        """The instance should be an instance of its class."""
        self.assertIsInstance(sched, schedule.ScheduledInterval)

    def test_ScheduledInterval_init_month(self):
        self._check_init(self.sched('month', 1))

    def test_ScheduledInterval_init_week(self):
        self._check_init(self.sched('week', 2))

    def test_ScheduledInterval_init_day(self):
        self._check_init(self.sched('days', 5))

    def test_ScheduledInterval_init_hour(self):
        self._check_init(self.sched('hours', 12))

    def test_ScheduledInterval_init_minute(self):
        self._check_init(self.sched('minute', 10))

    def test_ScheduledInterval_init_seconds(self):
        self._check_init(self.sched('seconds', 30))

    def test_ScheduledInterval_init_badIntervalPeriod(self):
        self.assertRaises(schedule.UnknownInterval,
                          self.sched, 'decades', 2)

    def test_ScheduledInterval_init_badIntervalCount(self):
        self.assertRaises(schedule.UnknownInterval,
                          self.sched, 'minutes', 'd20')

    def test_ScheduledInterval_init_negativeIntervalCount(self):
        sched = self.sched('days', -100000)
        self.assertEquals(sched.intervalCount, 1)
        self.assertEquals(sched.intervalPeriod, 'day')

    def test_ScheduledInterval_init_noargs(self):
        """Check that the defaults parameters function as expected."""
        sched = self.sched()
        self.assertEquals(sched.intervalCount, 1)
        self.assertEquals(sched.intervalPeriod, 'hour')

    def _check_intervalStart(self, period='second', count=30, variance=30):
        """Test the ScheduledInterval.intervalStart() method.

        :param str period: The interval type for the period.
        :param int count: The number of **period**s within an interval.
        :param int variance: The amount of variance (in seconds) to tolerate
            between the start of the interval containing now, and now.
        """
        now = int(self.now())
        sched = self.sched(period, count)
        time = sched.intervalStart(now)
        self.assertIsInstance(time, int)
        self.assertApproximates(now, time, variance)

    def test_ScheduledInterval_intervalStart_month(self):
        self._check_intervalStart('month', 1, 31*24*60*60)

    def test_ScheduledInterval_intervalStart_week(self):
        self._check_intervalStart('week', 2, 14*24*60*60)

    def test_ScheduledInterval_intervalStart_day(self):
        self._check_intervalStart('days', 5, 5*24*60*60)

    def test_ScheduledInterval_intervalStart_hour(self):
        self._check_intervalStart('hours', 12, 12*60*60)

    def test_ScheduledInterval_intervalStart_minute(self):
        self._check_intervalStart('minute', 10, 10*60)

    def test_ScheduledInterval_intervalStart_seconds(self):
        self._check_intervalStart('seconds', 30, 30)

    def _check_getInterval(self, period='second', count=30, variance=30):
        """Test the ScheduledInterval.getInterval() method.

        :param str period: The interval type for the period.
        :param int count: The number of **period**s within an interval.
        :param int variance: The amount of variance (in seconds) to tolerate
            between the start of the interval containing now, and now.
        """
        now = int(self.now())
        sched = self.sched(period, count)
        ts = sched.getInterval(now)
        self.assertIsInstance(ts, str)
        secs = [int(x) for x in ts.replace('-', ' ').replace(':', ' ').split()]
        [secs.append(0) for _ in xrange(6-len(secs))]
        secs = schedule.calendar.timegm(secs)
        self.assertApproximates(now, secs, variance)

    def test_ScheduledInterval_getInterval_month(self):
        self._check_getInterval('month', 2, 2*31*24*60*60)

    def test_ScheduledInterval_getInterval_week(self):
        self._check_getInterval('week', 1, 7*24*60*60)

    def test_ScheduledInterval_getInterval_day(self):
        self._check_getInterval('days', 4, 4*24*60*60)

    def test_ScheduledInterval_getInterval_hour(self):
        self._check_getInterval('hours', 23, 23*60*60)

    def test_ScheduledInterval_getInterval_minute(self):
        self._check_getInterval('minutes', 15, 15*60)

    def test_ScheduledInterval_getInterval_seconds(self):
        self._check_getInterval('seconds', 10, 60)

    def _check_nextIntervalStarts(self, period='second', count=30, variance=30):
        """Test the ScheduledInterval.nextIntervalStarts() method.

        :param str period: The interval type for the period.
        :param int count: The number of **period**s within an interval.
        :param int variance: The amount of variance (in seconds) to tolerate
            between the start of the interval containing now, and now.
        """
        now = int(self.now())
        sched = self.sched(period, count)
        time = sched.nextIntervalStarts(now)
        self.assertIsInstance(time, int)
        # (now + variance - time) should be > variance
        self.assertApproximates(now + variance, time, variance)

    def test_ScheduledInterval_nextIntervalStarts_month(self):
        self._check_nextIntervalStarts('month', 2, 2*31*24*60*60)

    def test_ScheduledInterval_nextIntervalStarts_week(self):
        self._check_nextIntervalStarts('week', 1, 7*24*60*60)

    def test_ScheduledInterval_nextIntervalStarts_day(self):
        self._check_nextIntervalStarts('days', 4, 4*24*60*60)

    def test_ScheduledInterval_nextIntervalStarts_hour(self):
        self._check_nextIntervalStarts('hours', 23, 23*60*60)

    def test_ScheduledInterval_nextIntervalStarts_minute(self):
        self._check_nextIntervalStarts('minutes', 15, 15*60)

    def test_ScheduledInterval_nextIntervalStarts_seconds(self):
        self._check_nextIntervalStarts('seconds', 10, 10)
