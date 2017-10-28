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

These tests are meant to ensure that the :mod:`bridgedb.persistent` module is
functioning as expected.
"""

from __future__ import print_function

import os.path

from copy import deepcopy
from io   import StringIO

from bridgedb import persistent
from bridgedb.parse.options import MainOptions
from twisted.python import log
from twisted.trial import unittest

import sure
from sure import this
from sure import the
from sure import expect


TEST_CONFIG_FILE = StringIO(unicode("""\
BRIDGE_FILES = ['bridge-descriptors', 'bridge-descriptors.new']
LOGFILE = 'bridgedb.log'"""))


class StateTest(unittest.TestCase):
    """Tests for :class:`bridgedb.persistent.State`."""

    timeout = 15

    def setUp(self):
        configuration = {}
        TEST_CONFIG_FILE.seek(0)
        compiled = compile(TEST_CONFIG_FILE.read(), '<string>', 'exec')
        exec compiled in configuration
        config = persistent.Conf(**configuration)

        fakeArgs = ['-c', os.path.join(os.getcwdu(), '..', 'bridgedb.conf')]
        options = MainOptions()
        options.parseOptions(fakeArgs)

        self.options = options
        self.config  = config
        self.state   = persistent.State(**config.__dict__)
        self.state.options = options
        self.state.config = config

    def test_configCreation(self):
        this(self.config).should.be.ok
        this(self.config).should.be.a(persistent.Conf)

    def test_optionsCreation(self):
        this(self.options).should.be.ok
        this(self.options).should.be.a(dict)

    def test_stateCreation(self):
        this(self.state).should.be.ok

        this(self.state).should.have.property('config').being.ok
        this(self.state).should.have.property('config').being.equal(self.config)

        this(self.state.options).should.be.ok
        this(self.state.options).should.equal(self.options)

    def test_docstring_persistent(self):
        persistent.should.have.property('__doc__').being.a(str)

    def test_docstring_persistentState(self):
        the(self.state).should.have.property('__doc__').being.a(str)

    def test_state_init(self):
        this(self.state).should.have.property('config')
        this(self.state).should.have.property('proxyList')
        this(self.state).should.have.property('statefile')

    def test_persistent_getState(self):
        persistent.should.have.property('_getState').being(callable)
        this(persistent._getState()).should.be.a(persistent.State)

    def test_getStateFor(self):
        jellyState = self.state.getStateFor(self)
        expect(jellyState).to.be.a(dict)
        expect(jellyState.keys()).to.contain('LOGFILE')

    def test_STATEFILE(self):
        this(self.state).should.have.property('statefile')
        the(self.state.statefile).should.be.a(str)

    def test_existsSave(self):
        this(self.state).should.have.property('save').being(callable)

    def test_existsLoad(self):
        persistent.should.have.property('load').being(callable)

    def test_persistent_state(self):
        the(persistent._state).should.be.a(persistent.State)

    def test_before_useChangedSettings_state(self):
        this(self.state).shouldnt.have.property('FOO')
        this(self.state).shouldnt.have.property('BAR')
        this(self.state).should.have.property('LOGFILE').being.a(str)
        this(self.state).should.have.property(
            'BRIDGE_FILES').being.a(list)

    def test_before_useChangedSettings_config(self):
        this(self.config).shouldnt.have.property('FOO')
        this(self.config).shouldnt.have.property('BAR')
        this(self.config).should.have.property('LOGFILE').being.a(str)
        this(self.config).should.have.property(
            'BRIDGE_FILES').being.a(list)

    def test_before_useChangedSettings_stateConfig(self):
        this(self.state.config).shouldnt.have.property('FOO')
        this(self.state.config).shouldnt.have.property('BAR')
        this(self.state.config).should.have.property('LOGFILE').being.a(str)
        this(self.state.config).should.have.property(
            'BRIDGE_FILES').being.a(list)

    def test_useChangedSettings(self):
        # This deepcopying must be done to avoid changing the State object
        # which is used for the rest of the tests.

        thatConfig = deepcopy(self.config)
        thatState  = deepcopy(self.state)

        setattr(thatConfig, 'FOO', 'fuuuuu')
        setattr(thatConfig, 'BAR', 'all of the things')
        setattr(thatConfig, 'LOGFILE', 42)

        this(thatConfig).should.have.property('FOO').being.a(basestring)
        this(thatConfig).should.have.property('BAR').being.a(basestring)
        this(thatConfig).should.have.property('LOGFILE').being.an(int)
        this(thatConfig).should.have.property('BRIDGE_FILES').being.a(list)

        the(thatConfig.FOO).must.equal('fuuuuu')
        the(thatConfig.BAR).must.equal('all of the things')
        the(thatConfig.LOGFILE).must.equal(42)

        the(thatState).should.have.property('useChangedSettings')
        the(thatState.useChangedSettings).should.be(callable)
        thatState.useChangedSettings(thatConfig)

        the(thatState.FOO).should.equal('fuuuuu')
        the(thatState).should.have.property('FOO').being.a(basestring)
        the(thatState).should.have.property('BAR').being.a(basestring)
        the(thatState).should.have.property('LOGFILE').being.an(int)
        the(thatState.FOO).must.equal(thatConfig.FOO)
        the(thatState.BAR).must.equal(thatConfig.BAR)
        the(thatState.LOGFILE).must.equal(thatConfig.LOGFILE)

        this(thatState.config).should.have.property('FOO')
        this(thatState.config).should.have.property('BAR')
        this(thatState.config).should.have.property('LOGFILE').being.an(int)
        this(thatState.config).should.have.property(
            'BRIDGE_FILES').being.a(list)
