# BridgeDB by Nick Mathewson.
# Copyright (c) 2007, The Tor Project, Inc.
# See LICENSE for licensing informatino

import doctest
import unittest
import warnings

import bridgedb.Bridges
import bridgedb.Main
import bridgedb.Dist
import bridgedb.Time

def suppressWarnings():
    warnings.filterwarnings('ignore', '.*tmpnam.*')

class TestCase0(unittest.TestCase):
    def testFooIsFooish(self):
        self.assert_(True)

def testSuite():
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()

    for klass in [ TestCase0 ]:
        suite.addTest(loader.loadTestsFromTestCase(klass))

    for module in [ bridgedb.Bridges,
                    bridgedb.Main,
                    bridgedb.Dist,
                    bridgedb.Time ]:
        suite.addTest(doctest.DocTestSuite(module))

    return suite

def main():
    suppressWarnings()
    
    unittest.TextTestRunner(verbosity=1).run(testSuite())



