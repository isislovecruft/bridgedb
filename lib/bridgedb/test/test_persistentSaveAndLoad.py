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
        # For some reason, twisted.trial.unittest.TestCase in Python2.6
        # doesn't have an 'assertItemsEqual' attribute...
        self.assertEqual(self.state.__dict__.keys().sort(),
                         loadedState.__dict__.keys().sort())

    def savedStateAssertions(self, savedStatefile=None):
        self.assertTrue(os.path.isfile(str(self.state.statefile)))
        if savedStatefile:
            self.assertTrue(os.path.isfile(str(savedStatefile)))

    def test_init_with_STATEFILE(self):
        config = self.config
        setattr(config, 'STATEFILE', '~/foo.state')
        state = persistent.State(**config.__dict__)
        self.loadedStateAssertions(state)
        statefile = state.statefile
        self.assertTrue(statefile.endswith('foo.state'))

    def test_init_without_config(self):
        state = persistent.State(None)
        self.loadedStateAssertions(state)

    def test_init_with_config(self):
        state = persistent.State(self.config)
        self.loadedStateAssertions(state)

    def test_get_statefile(self):
        statefile = self.state._get_statefile()
        self.assertIsInstance(statefile, basestring)

    def test_set_statefile(self):
        self.state._set_statefile('bar.state')
        statefile = self.state._get_statefile()
        self.assertIsInstance(statefile, basestring)

    def test_set_statefile_new_dir(self):
        config = self.config
        setattr(config, 'STATEFILE', 'statefiles/foo.state')
        state = persistent.State(**config.__dict__)
        self.loadedStateAssertions(state)
        statefile = state.statefile
        self.assertTrue(statefile.endswith('foo.state'))

    def test_del_statefile(self):
        self.state._set_statefile('baz.state')
        self.state._del_statefile()
        statefile = self.state._get_statefile()
        self.assertIsNone(statefile)

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

    def test_load_with_state(self):
        loadedState = persistent.load(self.state)
        self.loadedStateAssertions(loadedState)

    def test_load_with_None(self):
        persistent._setState(None)
        self.assertRaises(persistent.MissingState,
                          persistent.load, None)

    def test_load_with_statefile(self):
        self.assertRaises(persistent.MissingState,
                          self.state.load, 'quux.state')

    def test_load_with_statefile_opened(self):
        fh = open('quux.state', 'w+')
        self.assertRaises(persistent.MissingState, self.state.load, fh)
        fh.close()

    def test_load_with_statefile_object(self):
        self.assertRaises(persistent.MissingState, self.state.load, object)

    def test_load_without_statefile(self):
        persistent._setState(None)
        self.state.statefile = None
        self.assertRaises(persistent.MissingState,
                          persistent.load)
