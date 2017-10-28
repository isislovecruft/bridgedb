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

"""Unittests for the `bridgedb` commandline script."""

from __future__ import print_function

import os
import signal
import time

from twisted.trial import unittest
from twisted.trial.unittest import FailTest
from twisted.trial.unittest import SkipTest

from bridgedb.test.util import processExists
from bridgedb.test.util import getBridgeDBPID


class BridgeDBCliTest(unittest.TestCase):
    """Test the `bridgedb` command."""

    def setUp(self):
        here = os.getcwd()
        topdir = here.rstrip('_trial_temp')
        self.rundir = os.path.join(topdir, 'run')
        self.pidfile = os.path.join(self.rundir, 'bridgedb.pid')
        self.pid = getBridgeDBPID(self.pidfile)
        self.assignmentsFile = os.path.join(self.rundir, 'assignments.log')

    def doSleep(self):
        """Sleep for some ammount of time.

        We usually have less fake bridge descriptors with CI runs than we do
        during other tests, so we can safely decrease the sleep time on CI
        machines.
        """
        if os.environ.get("TRAVIS"):
            time.sleep(10)
        else:
            time.sleep(20)
        return

    def test_bridgedb_assignments_log(self):
        """This test should only be run if a BridgeDB server has already been
        started in another process.

        To see how this is done for the Travis CI tests, see the
        'before_script' section of the ``.travis.yml`` file in the top
        directory of this repository.

        This test ensures that an ``assignments.log`` file is created after a
        BridgeDB process was started.
        """
        if os.environ.get("CI"):
            if not self.pid or not processExists(self.pid):
                raise FailTest("Could not start BridgeDB process on CI server!")
        if not self.pid or not processExists(self.pid):
            raise SkipTest("Can't run test: no BridgeDB process running.")

        self.assertTrue(os.path.isfile(self.assignmentsFile))

    def test_bridgedb_SIGHUP_assignments_log(self):
        """Test that BridgeDB creates a new ``assignments.log`` file after
        receiving a SIGHUP.
        """
        if os.environ.get("CI"):
            if not self.pid or not processExists(self.pid):
                raise FailTest("Could not start BridgeDB process on CI server!")
        if not self.pid or not processExists(self.pid):
            raise SkipTest("Can't run test: no BridgeDB process running.")

        os.unlink(self.assignmentsFile)
        os.kill(self.pid, signal.SIGHUP)
        self.doSleep()
        self.assertTrue(os.path.isfile(self.assignmentsFile))

    def test_bridgedb_SIGUSR1_buckets(self):
        """Test that BridgeDB dumps buckets appropriately after a SIGUSR1."""
        if os.environ.get("CI"):
            if not self.pid or not processExists(self.pid):
                raise FailTest("Could not start BridgeDB process on CI server!")
        if not self.pid or not processExists(self.pid):
            raise SkipTest("Can't run test: no BridgeDB process running.")

        os.kill(self.pid, signal.SIGUSR1)
        self.doSleep()
        buckets = [['email', False], ['https', False], ['unallocated', False]]
        for rundirfile in os.listdir(self.rundir):
            for bucket in buckets:
                if rundirfile.startswith(bucket[0]):
                    bucket[1] = True
                    break
        for bucket in buckets:
            self.assertTrue(bucket[1], "%s bucket was not dumped!" % bucket[0])
