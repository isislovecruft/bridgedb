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


def generateDescriptors(count=None, rundir=None):
    """Run a script which creates fake bridge descriptors for testing purposes.

    This will run ``scripts/gen_bridge_descriptors`` to create bridge server
    descriptors, bridge extra-info descriptors, and networkstatus document.

    ** NOTE: **
        This function can take a very long time to run, especially in headless
        environments where entropy sources are minimal, because it creates the
        keys for each mocked OR, which are embedded in the server descriptors,
        used to calculate the OR fingerprints, and sign the descriptors, among
        other things.

    :param integer count: Number of mocked bridges to generate descriptor
        for. (default: 3)
    :type rundir: string or None
    :param rundir: If given, use this directory as the current working
        directory for the bridge descriptor generator script to run in. The
        directory MUST already exist, and the descriptor files will be created
        in it. If None, use the whatever directory we are currently in.
    """
    import subprocess
    import os.path

    proc = None
    script = 'gen_bridge_descriptors'
    rundir = rundir if os.path.isdir(rundir) else None
    count = count if count else 3
    try:
        proc = subprocess.Popen([script, '-n', str(count)],
                                close_fds=True, cwd=rundir)
    finally:
        if proc is not None:
            proc.wait()
            if proc.returncode:
                print("There was an error generating bridge descriptors.",
                      "(Returncode: %d)" % proc.returncode)
            else:
                print("Sucessfully bridge generated descriptors.")
    del subprocess

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

def doDumpBridges(config):
    """Dump bridges by assignment to a file.

    This function handles the commandline '--dump-bridges' option.

    :type config: :class:`bridgedb.Main.Conf`
    :param config: The current configuration.
    """
    import bridgedb.Bucket as bucket

    bucketManager = bucket.BucketManager(config)
    bucketManager.assignBridgesToBuckets()
    bucketManager.dumpBridges()
