# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: please see the AUTHORS file for attributions
# :copyright: (c) 2013-2015, Isis Lovecruft
#             (c) 2007-2015, The Tor Project, Inc.
# :license: see LICENSE for licensing information

"""Tests for :mod:`bridgedb.configure`."""

from __future__ import print_function

import os

from twisted.trial import unittest

from bridgedb import configure


class ConfigureTests(unittest.TestCase):
    """Tests for miscelaneous functions in :mod:`bridgedb.configure`."""

    def setUp(self):
        """Find the config file in the top directory of this repo."""
        here = os.getcwd()
        topdir = here.rstrip('_trial_temp')
        self.configFilename = os.path.join(topdir, 'bridgedb.conf')

    def test_loadConfig_with_file(self):
        """We should be able to load and parse the standard ``bridgedb.conf``
        file from the top directory of this repository.
        """
        config = configure.loadConfig(self.configFilename)
        self.assertTrue(config)

    def test_loadConfig_with_file_and_class(self):
        """We should be able to reload and parse the ``bridgedb.conf``
        file, if we have a config class as well.
        """
        config = configure.loadConfig(self.configFilename)
        newConfig = configure.loadConfig(self.configFilename, configCls=config)
        self.assertTrue(newConfig)

    def test_loadConfig_with_class(self):
        """We should be able to recreate a config, given its class."""
        config = configure.loadConfig(self.configFilename)
        newConfig = configure.loadConfig(configCls=config)
        self.assertTrue(newConfig)

    def test_loadConfig_set_EXTRA_INFO_FILES_when_None(self):
        """If certain options, like the ``EXTRA_INFO_FILES`` option in the
        config file weren't set, they should be made into lists so that our
        parsers don't choke on them later.
        """
        config = configure.loadConfig(self.configFilename)
        setattr(config, "EXTRA_INFO_FILES", None)
        self.assertTrue(config.EXTRA_INFO_FILES is None)
        newConfig = configure.loadConfig(configCls=config)
        self.assertIsInstance(newConfig.EXTRA_INFO_FILES, list)

    def test_loadConfig_returns_Conf(self):
        """After loading and parsing the ``bridgedb.conf`` file, we should have
        a :class:`bridgedb.configure.Conf`.
        """
        config = configure.loadConfig(self.configFilename)
        self.assertIsInstance(config, configure.Conf)
