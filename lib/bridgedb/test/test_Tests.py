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

import logging
import warnings

from twisted.trial import unittest

from bridgedb import Tests

logging.warnings.filterwarnings('ignore', module="Tests")
pyunit = __import__('unittest')


class OldUnittests(unittest.TestCase):
    """A wrapper around :mod:`bridgedb.Tests` to produce :mod:`~twisted.trial`
    compatible output.
    """

    def test_allOldUnittests(self):
        testSuite = Tests.testSuite()
        testResult = pyunit.TestResult()
        testSuite.run(testResult, debug=True)
        return unittest.PyUnitResultAdapter(testResult)
