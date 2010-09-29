#!/usr/bin/python
# BridgeDB by Nick Mathewson.
# Copyright (c) 2007-2009, The Tor Project, Inc.
# See LICENSE for licensing information

import distutils
import subprocess
from distutils.command.install_data import install_data as _install_data
import os
import sys

from distutils.core import setup, Command

class createTrans(Command):
    # Based on setup.py from 
    # http://wiki.maemo.org/Internationalize_a_Python_application
    description = "Install necessary translation files"
    user_options = []
    def initialize_options(self):
        pass
 
    def finalize_options(self):
        pass
 
    def run(self):
        po_dir = os.path.join(os.path.dirname(os.curdir), 'i18n')
        for path, dirnames, filenames in os.walk(po_dir):
            for d in dirnames:
                if d.endswith("templates"):
                    continue
                src = os.path.join('i18n', d, "bridgedb.po")
                lang = d
                dest_path = os.path.join('build', 'locale', lang, 'LC_MESSAGES')
                dest = os.path.join(dest_path, 'bridgedb.mo')
                if not os.path.exists(dest_path):
                    os.makedirs(dest_path)
                if not os.path.exists(dest):
                    print 'Compiling %s' % src
                    self.msgfmt(src, dest)
                else:
                    src_mtime = os.stat(src)[8]
                    dest_mtime = os.stat(dest)[8]
                    if src_mtime > dest_mtime:
                        print 'Compiling %s' % src
                        self.msgfmt(src, dest)
    def msgfmt(self, src, dest):
        args = src + " -o " + dest
        try:
            ret = subprocess.call("msgfmt" + " " + args, shell=True)
            if ret < 0:
                print 'Error in msgfmt execution: %s' % ret
        except OSError, e:
            print 'Comilation failed: ' % e

class installData(_install_data):
    def run(self):
        self.data_files = []
        for lang in os.listdir('build/locale/'):
            if lang.endswith('templates'):
                continue
            lang_dir = os.path.join('share', 'locale', lang, 'LC_MESSAGES')
            lang_file = os.path.join('build', 'locale', lang, 'LC_MESSAGES', 
                                     'bridgedb.mo')
            self.data_files.append( (lang_dir, [lang_file]) )
        _install_data.run(self)

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
      cmdclass={'test' : runTests,
                'trans': createTrans,
                'install_data': installData}
      )


