# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013, Isis Lovecruft
#             (c) 2007-2013, The Tor Project, Inc.
#             (c) 2007-2013, all entities within the AUTHORS file
# :license: 3-Clause BSD, see LICENSE for licensing information

"""Class wrappers to adapt BridgeDB old unittests in :mod:`bridgedb.Tests` to
be compatible with the newer :mod:`twisted.trial` unittests in this directory.
"""

from __future__ import print_function
from __future__ import unicode_literals

import doctest
import glob
import logging
import os
import warnings

from twisted.trial import unittest

from bridgedb import Tests

logging.warnings.filterwarnings('ignore', module="Tests")
pyunit = __import__('unittest')


def generateTrialAdaptedDoctestsSuite():
    """Dynamically generates a :class:`unittest.TestSuite` all containing
    discovered doctests within the installed ``bridgedb`` package.
    """
    bridgedb     = __import__('bridgedb')
    fakedGlobals = globals().update({'bridgedb': bridgedb})
    modulePath   = bridgedb.__path__[0]

    #: The package directories to search for source code with doctests.
    packagePaths = [modulePath,
                    os.path.join(modulePath, 'parse'),
                    os.path.join(modulePath, 'test')]
    #: The source code files which will be searched for doctests.
    files = []
    #: The cls.testSuites which the test methods will be generated from.
    testSuites = []

    packages = [os.path.join(pkg, '*.py') for pkg in packagePaths]
    [files.extend(glob.glob(pkg)) for pkg in packages]

    for filename in files:
        testSuites.append(
            doctest.DocFileSuite(filename,
                                 module_relative=False,
                                 globs=fakedGlobals))
    return testSuites


class OldUnittests(unittest.TestCase):
    """A wrapper around :mod:`bridgedb.Tests` to produce :mod:`~twisted.trial`
    compatible output.
    """

    def test_allOldUnittests(self):
        testSuite = Tests.testSuite()
        testResult = pyunit.TestResult()
        testSuite.run(testResult, debug=True)
        return unittest.PyUnitResultAdapter(testResult)
