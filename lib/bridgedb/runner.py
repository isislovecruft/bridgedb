# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2013, The Tor Project, Inc.
#             (c) 2007-2013, all entities within the AUTHORS file
# :license: 3-clause BSD, see included LICENSE for information

"""Classes for running components and servers, as well as daemonisation.

** Module Overview: **

"""

from __future__ import print_function

import sys


def generateDescriptors(howmany):
    """Run a script which creates fake bridge descriptors for testing purposes.

    This will run scripts/gen_bridge_descriptors to create a bridge router
    descriptors, bridge extrainfo descriptors, a consensus document, and a
    networkstatus document.

    :param integer howmany: Number of fake bridges to generate descriptor for.
    :rtype: integer
    :returns: The process returncode from the gen_bridge_descriptors script.
    """
    import subprocess

    try:
        print("Generating %s bridge descriptors..." % str(howmany))
        proc = subprocess.Popen(['gen_bridge_descriptors', str(howmany)],
                                stdout=sys.stdout, stderr=sys.stderr)
    except Exception as exc:
        print(exc)
        print("There was an error generating bridge descriptors.")
    else:
        proc.wait()
        if proc.returncode:
            print("There was an error generating bridge descriptors. (%s: %d)"
                  % ("Returncode", proc.returncode))
        else:
            print("Sucessfully bridge generated descriptors.")
    finally:
        del subprocess
    return

def runTrial(options):
    """Run Twisted trial based unittests, optionally with coverage.

    :type options: :class:`~bridgedb.opt.TestOptions`
    :param options: Parsed options for controlling the twisted.trial test
        run. All unrecognised arguments after the known options will be passed
        along to trial.
    """
    from twisted.scripts import trial

    # Insert 'trial' as the first system cmdline argument:
    sys.argv = ['trial']

    if options['coverage']:
        try:
            from coverage import coverage
        except ImportError as ie:
            print(ie.message)
        else:
            cov = coverage()
            cov.start()
            sys.argv.append('--coverage')
            sys.argv.append('--reporter=bwverbose')

    # Pass all arguments along to its options parser:
    if 'test_args' in options:
        for arg in options['test_args']:
            sys.argv.append(arg)
    # Tell trial to test the bridgedb package:
    sys.argv.append('bridgedb.test')
    trial.run()

    if options['coverage']:
        cov.stop()
        cov.html_report('_trial_temp/coverage/')

def runTests(options):
    """Run unittest based tests.

    :type options: :class:`~bridgedb.opt.TestOptions`
    :param options: Parsed options for controlling the twisted.trial test
        run. All unrecognised arguments after the known options will be passed
        along to trial.
    """
    testModule = __import__('bridgedb.Tests', globals(), '', [])
    testModule.Tests.main()
