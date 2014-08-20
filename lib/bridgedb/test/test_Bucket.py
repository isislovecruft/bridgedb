# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :copyright: (c) 2007-2014, The Tor Project, Inc.
#             (c) 2007-2014, all entities within the AUTHORS file
# :license: 3-Clause BSD, see LICENSE for licensing information

"""Unittests for the :mod:`bridgedb.Bucket` module.

These tests are meant to ensure that the :mod:`bridgedb.Bucket` module is
functioning as expected.
"""

from __future__ import print_function

import sure
from sure import this
from sure import the
from sure import expect

from bridgedb import Bucket

from twisted.trial import unittest


class BucketDataTest(unittest.TestCase):
    """Tests for :class:`bridgedb.Bucket.BucketData`."""

    def test_alloc_some_of_the_bridges(self):
        """Set the needed number of bridges"""
        alloc = 10
        distname = "test-distributor"
        bucket = Bucket.BucketData(distname, alloc)
        this(distname).should.be.equal(bucket.name)
        this(alloc).should.be.equal(bucket.needed)

    def test_alloc_all_the_bridges(self):
        """Set the needed number of bridges to the default"""
        alloc = '*'
        distname = "test-distributor"
        bucket = Bucket.BucketData(distname, alloc)
        this(distname).should.be.equal(bucket.name)
        this(alloc).should.be.equal(1000000)


class BucketManagerTest(unittest.TestCase):
    """Tests for :class:`bridgedb.Bucket.BucketManager`."""
    TEST_CONFIG_FILE = StringIO(unicode("""\
    FILE_BUCKETS = { 'test1': 7, 'test2': 11 }
    COLLECT_TIMESTAMPS = False
    COUNTRY_BLOCK_FILE = []"""))

    def setUp(self):
        configuration = {}
        TEST_CONFIG_FILE.seek(0)
        compiled = compile(TEST_CONFIG_FILE.read(), '<string>', 'exec')
        exec compiled in configuration
        self.config = persistent.Conf(**configuration)
        self.state   = persistent.State(**config.__dict__)
        self.bucket = Bucket.BucketManager(self.config)
