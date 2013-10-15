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

import sys
import textwrap

from twisted.python import usage

# from ._version import get_versions
# __version__ = get_versions()['version']
# del get_versions
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
    private relays acting as bridges into the Tor network.""")

    optFlags = [['verbose', 'v', 'Log to stdout']]

    def __init__(self):
        """Create an options parser. All flags, parameters, and attributes of
        this base options parser are inherited by all child classes.
        """
        usage.Options.__init__(self)
        self['version'] = self.opt_version

    def opt_version(self):
        """Display BridgeDB version and exit."""
        print("%s-%s" % (__package__, __version__))
        sys.exit()


class TestOptions(BaseOptions):
    """Suboptions for running twisted.trial and unittest based tests."""

    optFlags = [['coverage', 'c', 'Generate coverage statistics']]
    optParameters = [
        ['descriptors', 'n', 1000, 'Generate <N> fake bridge descriptors'],
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


class MainOptions(BaseOptions):
    """Main commandline options parser for BridgeDB."""

    optFlags = [
        ['reload', 'r',
         'Reload bridge descriptors by sending a SIGHUP to BridgeDB'],
        ['dump-bridges', 'd', 'Dump bridges by hashring assignment into files']]
    optParameters = [
        ['config', 'c', './bridgedb.conf', 'Configuration file']]

    subCommands = [
        ['test', None, TestOptions,
         "Run twisted.trial tests or unittests (see `bridgedb test --help`)"]]
