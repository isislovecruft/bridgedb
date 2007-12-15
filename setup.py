# BridgeDB by Nick Mathewson.
# Copyright (c) 2007, The Tor Project, Inc.
# See LICENSE for licensing information

import distutils
import sys

from distutils.core import setup, Command

class runTests(Command):
    # Based on setup.py from mixminion, which is based on setup.py
    # from Zooko's pyutil package, which is in turn based on
    # http://mail.python.org/pipermail/distutils-sig/2002-January/002714.html
    description = "Run unit tests"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        build = self.get_finalized_command('build')
        self.build_purelib = build.build_purelib
        self.build_platlib = build.build_platlib

    def run(self):
        self.run_command('build')
        old_path = sys.path[:]
        sys.path[0:0] = [ self.build_purelib, self.build_platlib ]
        try:
            testmod = __import__("bridgedb.Tests", globals(), "", [])
            testmod.Tests.main()
        finally:
            sys.path = old_path

setup(name='BridgeDB',
      version='0.1',
      description='Bridge disbursal tool for use with Tor anonymity network',
      author='Nick Mathewson',
      author_email='nickm at torproject dot org',
      url='https://www.torproject.org',
      package_dir= {'' : 'lib'},
      packages=['bridgedb'],
      py_modules=['TorBridgeDB'],
      cmdclass={'test' : runTests}
      )


