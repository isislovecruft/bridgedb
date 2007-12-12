# BridgeDB by Nick Mathewson.
# Copyright (c) 2007, The Tor Project, Inc.
# See LICENSE for licensing informatino

import distutils
from distutils.core import setup

setup(name='BridgeDB',
      version='0.1',
      description='Bridge disbursal tool for use with Tor anonymity network',
      author='Nick Mathewson',
      author_email='nickm at torproject dot org',
      url='https://www.torproject.org',
      package_dir= {'' : 'lib'},
      packages=['bridgedb'])


