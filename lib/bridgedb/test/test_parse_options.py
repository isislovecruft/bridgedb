# -*- coding: utf-8 -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2014-2015, The Tor Project, Inc.
#             (c) 2014-2015, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""Unittests for :mod:`bridgedb.parse.options`."""


from __future__ import print_function

import os
import sys

from twisted.python.usage import UsageError
from twisted.trial import unittest

from bridgedb.parse import options


class ParseOptionsTests(unittest.TestCase):
    """Unittests for :mod:`bridgedb.parse.options`."""

    def setUp(self):
        """Replace the current sys.argv's for the run of this test, and
        redirect sys.stdout to os.devnull to prevent the options parser from
        printing the --help a bunch of times.
        """
        # Make sure a config file is in the current directory, or else the
        # argument parser will get angry and throw another SystemExit
        # exception.
        with open(os.path.join(os.getcwd(), 'bridgedb.conf'), 'a+') as fh:
            fh.write('\n')

        self.oldSysArgv = sys.argv
        self.oldStdout = sys.stdout
        sys.stdout = open(os.devnull, 'w')

    def tearDown(self):
        """Put the original sys.argv's back."""
        sys.stdout.close()  # Actually closes the FD we opened for /dev/null
        sys.argv = self.oldSysArgv
        sys.stdout = self.oldStdout
        self.oldSysArgv = None
        self.oldStdout = None

    def test_parse_options_parseOptions_with_invalid_options(self):
        """:func:`options.parseOptions` should raise SystemExit because
        the args 'somearg anotherarg' are invalid commands.
        """
        fakeSysArgv = ['somearg', 'anotherarg']
        sys.argv = fakeSysArgv
        self.assertRaises(SystemExit, options.parseOptions)

    def test_parse_options_parseOptions_with_valid_options(self):
        """:func:`options.parseOptions` should return a
        :class:`options.MainOptions` when given valid commandline arguments.
        """
        fakeSysArgv = ['bridgedb', 'mock', '-n', '-1']
        sys.argv = fakeSysArgv
        opts = options.parseOptions()
        self.assertIsInstance(opts, options.MainOptions)

    def test_parse_options_parseOptions_verbosity_quiet_quiet(self):
        """If we use `-q` twice on the commandline, ``opts['verbosity']``
        should equal ``10``.
        """
        fakeSysArgv = ['bridgedb', '-q', '-q', 'mock', '-n', '-1']
        sys.argv = fakeSysArgv
        opts = options.parseOptions()
        self.assertEqual(opts['verbosity'], 10)

    def test_parse_options_parseOptions_verbosity_verbose(self):
        """If we use `-v` once on the commandline, ``opts['verbosity']``
        should equal ``50``.
        """
        fakeSysArgv = ['bridgedb', '-v', '-v', 'mock', '-n', '-1']
        sys.argv = fakeSysArgv
        opts = options.parseOptions()
        self.assertEqual(opts['verbosity'], 50)

    def test_parse_options_parseOptions_rundir(self):
        """The automatic rundir should be our current directory."""
        fakeSysArgv = ['bridgedb', 'mock', '-n', '-1']
        sys.argv = fakeSysArgv
        opts = options.parseOptions()
        self.assertEqual(opts['rundir'], os.getcwd())

    def test_parse_options_parseOptions_version(self):
        """:func:`options.parseOptions` when given a `--version` argument on
        the commandline, should raise SystemExit (after printing some stuff,
        but we don't care what it prints).
        """
        fakeSysArgv = ['bridgedb', '--version']
        sys.argv = fakeSysArgv
        self.assertRaises(SystemExit, options.parseOptions)
