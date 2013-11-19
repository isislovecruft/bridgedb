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

"""Unittests for the :mod:`bridgedb.persistent` module.

These tests ensure that :meth:`bridgedb.persistent.State.save`,
:func:`bridgedb.persistent.load`, and :meth:`bridgedb.persistent.State.load`
are all functioning as expected.

This module should not import :mod:`sure`.
"""

import os

from copy import deepcopy
from io    import StringIO

from twisted.trial import unittest

from bridgedb import persistent


TEST_CONFIG_FILE = StringIO(unicode("""\
BRIDGE_FILES = ['bridge-descriptors', 'bridge-descriptors.new']
LOGFILE = 'bridgedb.log'"""))


class StateSaveAndLoadTests(unittest.TestCase):
    """Test save() and load() of :mod:`~bridgedb.persistent`."""

    timeout = 15

    def setUp(self):
        configuration = {}
        TEST_CONFIG_FILE.seek(0)
        compiled = compile(TEST_CONFIG_FILE.read(), '<string>', 'exec')
        exec compiled in configuration
        config = persistent.Conf(**configuration)

        self.config = config
        self.state  = persistent.State(**config.__dict__)
        self.state.config = config
        self.state.statefile = os.path.abspath('bridgedb.state')

    def loadedStateAssertions(self, loadedState):
        # For some reason, twisted.trial.unittest.TestCase in Python2.6
        # doesn't have an 'assertIsNotNone' attribute...
        self.assertTrue(loadedState is not None)
        self.assertIsInstance(loadedState, persistent.State)
        self.assertNotIdentical(self.state, loadedState)
        self.assertNotEqual(self.state, loadedState)
        self.assertItemsEqual(self.state.__dict__.keys(),
                              loadedState.__dict__.keys())

    def savedStateAssertions(self, savedStatefile=None):
        self.assertTrue(os.path.isfile(str(self.state.statefile)))
        if savedStatefile:
            self.assertTrue(os.path.isfile(str(savedStatefile)))

    def test_save(self):
        self.state.save()
        self.savedStateAssertions()

    def test_stateSaveTempfile(self):
        savefile = self.mktemp()
        self.state.statefile = savefile
        self.state.save(savefile)
        savedStatefile = str(self.state.statefile)

    def test_stateLoadTempfile(self):
        savefile = self.mktemp()
        self.state.statefile = savefile
        self.assertTrue(self.state.statefile.endswith(savefile))
        self.state.save(savefile)
        self.savedStateAssertions(savefile)
        loadedState = self.state.load(savefile)
        self.loadedStateAssertions(loadedState)

    def test_stateSaveAndLoad(self):
        self.state.save()
        loadedState = self.state.load()
        self.loadedStateAssertions(loadedState)

    def test_load(self):
        self.state.save()
        loadedState = persistent.load()     
        self.loadedStateAssertions(loadedState)
