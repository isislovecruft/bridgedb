# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2013, The Tor Project, Inc.
#             (c) 2007-2013, all entities within the AUTHORS file
# :license: 3-clause BSD, see included LICENSE for information

"""Parsers for BridgeDB commandline options.

.. py:module:: bridgedb.parse.options
   :synopsis: Parsers for BridgeDB commandline options.


bridgedb.parse.options
======================
::

  bridgedb.parse.options
   |__ setConfig()
   |__ getConfig() - Set/Get the config file path.
   |__ setRundir()
   |__ getRundir() - Set/Get the runtime directory.
   |__ parseOptions() - Create the main options parser for BridgeDB.
   |
   \_ BaseOptions - Base options, included in all other options menus.
       ||
       |\__ findRundirAndConfigFile() - Find the absolute path of the config
       |                                file and runtime directory, or find
       |                                suitable defaults.
       |
       |__ SIGHUPOptions - Menu to explain SIGHUP signal handling and usage.
       |__ SIGUSR1Options - Menu to explain SIGUSR1 handling and usage.
       |
       |__ MockOptions - Suboptions for creating fake bridge descriptors for
       |                 testing purposes.
       |__ TestOptions - Suboptions for running twisted.trial based unittests.
       \__ MainOptions - Main commandline options parser for BridgeDB.
..
"""

from __future__ import print_function
from __future__ import unicode_literals

import sys
import textwrap
import traceback
import os

from twisted.python import usage

from bridgedb import __version__


#: In :meth:`BaseOptions.findRundirAndConfig`, this is set to the the
#: absolute path of the ``opts['rundir']`` setting, if given, otherwise it
#: defaults to the current directory.
_rundir = None

#: In :meth:`BaseOptions.findRundirAndConfig`, if ``opts['config']`` is
#: given, this is set to the the absolute path of the ``opts['config']``
#: settting relative to the ``rundir``, otherwise it defaults to
#: 'bridgedb.conf' in the current directory.
_config = None


def setConfig(path):
    """Set the absolute path to the config file.

    See :meth:`BaseOptions.postOptions`.

    :param string path: The path to set.
    """
    global _config
    _config = path

def getConfig():
    """Get the absolute path to the config file.

    :rtype: string
    :returns: The path to the config file.
    """
    return _config

def setRundir(path):
    """Set the absolute path to the runtime directory.

    See :meth:`BaseOptions.postOptions`.

    :param string path: The path to set.
    """
    global _rundir
    _rundir = path

def getRundir():
    """Get the absolute path to the runtime directory.

    :rtype: string
    :returns: The path to the config file.
    """
    return _rundir

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
        print(options.getUsage())
        sys.exit(1)
    except Exception as error:  # pragma: no cover
        exc, value, tb = sys.exc_info()
        print("Unhandled Error: %s" % error.message)
        print(traceback.format_exc(tb))

    return options


class BaseOptions(usage.Options):
    """Base options included in all main and sub options menus."""

    longdesc = textwrap.dedent("""BridgeDB is a proxy distribution system for
    private relays acting as bridges into the Tor network. See `bridgedb
    <command> --help` for addition help.""")

    optParameters = [
        ['config', 'c', None,
         'Configuration file [default: <rundir>/bridgedb.conf]'],
        ['rundir', 'r', None,
         """Change to this directory before running. [default: `os.getcwd()']

         All other paths, if not absolute, should be relative to this path.
         This includes the config file and any further files specified within
         the config file.
         """]]

    def __init__(self):
        """Create an options parser. All flags, parameters, and attributes of
        this base options parser are inherited by all child classes.
        """
        super(BaseOptions, self).__init__()
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
        sys.exit(0)

    @staticmethod
    def findRundirAndConfigFile(rundir=None, config=None):
        """Find the absolute path of the config file and runtime directory, or
        find suitable defaults.

        Attempts to set the absolute path of the runtime directory. If the
        config path is relative, its absolute path is set relative to the
        runtime directory path (unless it starts with '.' or '..', then it is
        interpreted relative to the current working directory). If the path to
        the config file is absolute, it is left alone.

        :type rundir: string or None
        :param rundir: The user-supplied path to the runtime directory, from
            the commandline options (i.e.
            ``options = BaseOptions().parseOptions(); options['rundir'];``).
        :type config: string or None
        :param config: The user-supplied path to the config file, from the
            commandline options (i.e.
            ``options = BaseOptions().parseOptions(); options['config'];``).
        :raises: :api:`twisted.python.usage.UsageError` if either the runtime
            directory or the config file cannot be found.
        """
        gRundir = getRundir()
        gConfig = getConfig()

        if gRundir is None:
            if rundir is not None:
                gRundir = os.path.abspath(os.path.expanduser(rundir))
            else:
                gRundir = os.getcwdu()
        setRundir(gRundir)

        if not os.path.isdir(gRundir):  # pragma: no cover
            raise usage.UsageError(
                "Could not change to runtime directory: `%s'" % gRundir)

        if gConfig is None:
            if config is None:
                config = 'bridgedb.conf'
            gConfig = config

            if not os.path.isabs(gConfig):
                # startswith('.') will handle other relative paths, i.e. '..'
                if gConfig.startswith('.'):  # pragma: no cover
                    gConfig = os.path.abspath(os.path.expanduser(gConfig))
                else:
                    gConfig = os.path.join(gRundir, gConfig)
        setConfig(gConfig)

        gConfig = getConfig()
        if not os.path.isfile(gConfig):  # pragma: no cover
            raise usage.UsageError(
                "Specified config file `%s' doesn't exist!" % gConfig)

    def postOptions(self):
        """Automatically called by :meth:`parseOptions`.

        Determines appropriate values for the 'config' and 'rundir' settings.
        """
        super(BaseOptions, self).postOptions()
        self.findRundirAndConfigFile(self['rundir'], self['config'])

        gConfig = getConfig()
        gRundir = getRundir()

        if (self['rundir'] is None) and (gRundir is not None):
            self['rundir'] = gRundir

        if (self['config'] is None) and (gConfig is not None):
            self['config'] = gConfig

        if self['verbosity'] <= 10:
            print("%s.postOptions():" % self.__class__)
            print("  gCONFIG=%s" % gConfig)
            print("  self['config']=%s" % self['config'])
            print("  gRUNDIR=%s" % gRundir)
            print("  self['rundir']=%s" % self['rundir'])


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


class SIGHUPOptions(BaseOptions):
    """Options menu to explain usage and handling of SIGHUP signals."""

    longdesc = """If you send a SIGHUP to a running BridgeDB process, the
    servers will parse and reload all bridge descriptor files into the
    databases.

    Note that this command WILL NOT handle sending the signal for you; see
    signal(7) and kill(1) for additional help."""


class SIGUSR1Options(BaseOptions):
    """Options menu to explain usage and handling of SIGUSR1 signals."""

    longdesc = """If you send a SIGUSR1 to a running BridgeDB process, the
    servers will dump all bridge assignments by distributor from the
    databases to files.

    Note that this command WILL NOT handle sending the signal for you; see
    signal(7) and kill(1) for additional help."""


class MainOptions(BaseOptions):
    """Main commandline options parser for BridgeDB."""

    optFlags = [
        ['dump-bridges', 'd', 'Dump bridges by hashring assignment into files'],
        ['reload', 'R', 'Reload bridge descriptors into running servers']]
    subCommands = [
        ['test', None, TestOptions, "Run twisted.trial tests or unittests"],
        ['mock', None, MockOptions, "Generate a testing environment"],
        ['SIGHUP', None, SIGHUPOptions,
         "Reload bridge descriptors into running servers"],
        ['SIGUSR1', None, SIGUSR1Options,
         "Dump bridges by hashring assignment into files"]]
