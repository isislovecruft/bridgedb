# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2013, The Tor Project, Inc.
#             (c) 2007-2013, all entities within the AUTHORS file
# :license: 3-clause BSD, see included LICENSE for information

"""Classes for commandline options parsing.

** Module Overview: **

"""

from __future__ import print_function
from __future__ import unicode_literals

import sys
import textwrap
import os

from twisted.python import usage

from bridgedb import __version__


def parseOptions():
    """Create the main options parser and its subcommand parsers.

    Any :exc:`~twisted.python.usage.UsageErrors` which are raised due to
    invalid options are ignored; their error message is printed and then we
    exit the program.

    :rtype: :class:`MainOptions`
    :returns: The main options parsing class, with any commandline arguments
        already parsed.
    """
    options = MainOptions()
    try:
        options.parseOptions()
    except usage.UsageError as uerr:
        print(uerr.message)
        sys.exit(1)
    return options


class BaseOptions(usage.Options):
    """Base options included in all main and sub options menus."""

    longdesc = textwrap.dedent("""BridgeDB is a proxy distribution system for
    private relays acting as bridges into the Tor network. See `bridgedb
    <command> --help` for addition help.""")

    def opt_rundir(self, rundir):
        """Change to this directory"""
        if not rundir:
            rundir = os.getcwdu()
        else:
            try:
                rundir = os.path.abspath(os.path.expanduser(rundir))
            except Exception as error:
                raise usage.UsageError(error.message)
        if rundir and os.path.isdir(rundir):
            self['rundir'] = rundir
    opt_r = opt_rundir

    def __init__(self):
        """Create an options parser. All flags, parameters, and attributes of
        this base options parser are inherited by all child classes.
        """
        usage.Options.__init__(self)
        self['rundir'] = os.getcwdu()
        self['version'] = self.opt_version
        self['verbosity'] = 30

    def opt_quiet(self):
        """Decrease verbosity"""
        # We use '10' because then it corresponds to the log levels
        self['verbosity'] -= 10

    def opt_verbose(self):
        """Increase verbosity"""
        self['verbosity'] += 10

    opt_q = opt_quiet
    opt_v = opt_verbose

    def opt_version(self):
        """Display BridgeDB's version and exit."""
        print("%s-%s" % (__package__, __version__))
        sys.exit()


class TestOptions(BaseOptions):
    """Suboptions for running twisted.trial and unittest based tests."""

    longdesc = textwrap.dedent("""BridgeDB testing commands.
    See the `bridgedb mock` command for generating testing environments.""")

    optFlags = [['coverage', 'c', 'Generate coverage statistics']]
    optParameters = [
        ['file', 'f', None, 'Run tests in specific file(s) (trial only)'],
        ['unittests', 'u', False, 'Run unittests in bridgedb.Tests'],
        ['trial', 't', True, 'Run twisted.trial tests in bridgedb.test']]

    completionData = usage.Completions(
        mutuallyExclusive=[('unittests', 'coverage'),
                           ('unittests', 'file')],
        optActions={'file': usage.CompleteFiles('lib/bridgedb/test/test_*.py',
                                                repeat=True,
                                                descr="test filename")},
        extraActions=[
            usage.Completer(descr="extra arguments to pass to trial")])

    def parseArgs(self, *args):
        """Parse any additional arguments after the options and flags."""
        self['test_args'] = args

class MockOptions(BaseOptions):
    """Suboptions for creating necessary conditions for testing purposes."""

    optParameters = [
        ['descriptors', 'n', 1000,
         '''Generate <n> mock bridge descriptor sets
          (types: netstatus, extrainfo, server)''']]


class MainOptions(BaseOptions):
    """Main commandline options parser for BridgeDB."""

    optFlags = [
        ['dump-bridges', 'd', 'Dump bridges by hashring assignment into files'],
        ['reload', 'R', 'Reload bridge descriptors into running servers']]
    optParameters = [
        ['config', 'c', 'bridgedb.conf', 'Configuration file']]
    subCommands = [
        ['test', None, TestOptions, "Run twisted.trial tests or unittests"],
        ['mock', None, MockOptions, "Generate a testing environment"]]
