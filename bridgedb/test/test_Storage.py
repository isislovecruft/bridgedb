#!/usr/bin/env python
"""Unittests for the :mod:`bridgedb.Storage` module."""

import os
import threading
import time

from twisted.python import log
from twisted.trial import unittest
from twisted.internet import reactor
from twisted.internet.threads import deferToThread

import bridgedb.Storage as Storage

from bridgedb.test.util import generateFakeBridges

class DatabaseTest(unittest.TestCase):
    def setUp(self):
        self.fakeBridges = generateFakeBridges()
        self.validRings = ['https', 'unallocated', 'email', 'moat']
        self.dbfname = 'test-bridgedb.sqlite'
        Storage.setDBFilename(self.dbfname)

    def tearDown(self):
        if os.path.isfile(self.dbfname):
            os.unlink(self.dbfname)
        Storage.clearGlobalDB()

    def _runAndDie(self, timeout, func):
        with func():
            time.sleep(timeout)

    def _cb_assertTrue(self, result):
        self.assertTrue(result)

    def _cb_assertFalse(self, result):
        self.assertFalse(result)

    def _eb_Failure(self, failure):
        self.fail(failure)

    def test_getDB_FalseWhenLocked(self):
        Storage._LOCK = threading.Lock()
        Storage._LOCK.acquire()
        self.assertFalse(Storage._LOCK.acquire(False))

    def test_getDB_AcquireLock(self):
        Storage.initializeDBLock()
        with Storage.getDB() as db:
            self.assertIsInstance(db, Storage.Database)
            self.assertTrue(Storage.dbIsLocked())
            self.assertEqual(db, Storage._OPENED_DB)

    def test_getDB_ConcurrencyLock(self):
        timeout = 1
        d1 = deferToThread(self._runAndDie, timeout, Storage.getDB)
        d1.addCallback(self._cb_assertFalse)
        d1.addErrback(self._eb_Failure)
        d2 = deferToThread(Storage.getDB, False)
        d2.addCallback(self._cb_assertFalse)
        d2.addErrback(self._eb_Failure)
        d2.addCallback(self._cb_assertTrue, Storage.getDB(False))

    def test_insertBridgeAndGetRing_new_bridge(self):
        bridge = self.fakeBridges[0]
        Storage.initializeDBLock()
        with Storage.getDB() as db:
            ringname = db.insertBridgeAndGetRing(bridge, 'moat',
                                                 time.time(),
                                                 self.validRings)
            self.assertIn(ringname, self.validRings)

    def test_insertBridgeAndGetRing_already_seen_bridge(self):
        bridge = self.fakeBridges[0]
        Storage.initializeDBLock()
        with Storage.getDB() as db:
            ringname = db.insertBridgeAndGetRing(bridge, 'moat',
                                                 time.time(),
                                                 self.validRings)
            self.assertIn(ringname, self.validRings)
            ringname = db.insertBridgeAndGetRing(bridge, 'https',
                                                 time.time(),
                                                 self.validRings)
            self.assertIn(ringname, self.validRings)
            self.assertEqual(ringname, 'moat')

    def test_getBridgeDistributor_recognised(self):
        bridge = self.fakeBridges[0]
        Storage.initializeDBLock()
        with Storage.getDB() as db:
            ringname = db.insertBridgeAndGetRing(bridge, 'moat',
                                                 time.time(),
                                                 self.validRings)
            self.assertIn(ringname, self.validRings)
            self.assertEqual(ringname, 'moat')
            db.commit()

        with Storage.getDB() as db:
            ringname = db.getBridgeDistributor(bridge, self.validRings)
            self.assertEqual(ringname, 'moat')

    def test_getBridgeDistributor_unrecognised(self):
        bridge = self.fakeBridges[0]
        Storage.initializeDBLock()
        with Storage.getDB() as db:
            ringname = db.insertBridgeAndGetRing(bridge, 'godzilla',
                                                 time.time(),
                                                 self.validRings)
            self.assertIn(ringname, self.validRings)
            self.assertEqual(ringname, "unallocated")
            db.commit()

        with Storage.getDB() as db:
            ringname = db.getBridgeDistributor(bridge, self.validRings)
            self.assertEqual(ringname, "unallocated")
