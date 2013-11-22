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

import logging
import warnings

from twisted.trial import unittest

from bridgedb import Tests
from bridgedb.Tests import EmailBridgeDistTests
from bridgedb.Tests import IPBridgeDistTests
from bridgedb.Tests import DictStorageTests
from bridgedb.Tests import SQLStorageTests
from bridgedb.Tests import ParseDescFileTests
from bridgedb.Tests import BridgeStabilityTests

logging.warnings.filterwarnings('ignore', module="Tests")
pyunit = __import__('unittest')


class TrialAdaptedOldUnittests(unittest.TestCase):

    def test_allOldUnittests(self):
        testSuite = Tests.testSuite()
        testResult = pyunit.TestResult()
        testSuite.run(testresult, debug=True)
        return unittest.PyUnitResultAdapter(testresult)

