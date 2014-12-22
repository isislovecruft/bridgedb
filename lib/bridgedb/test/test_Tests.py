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

"""Class wrappers to adapt BridgeDB old unittests in :mod:`bridgedb.Tests`
(now kept in :mod:`bridgedb.test.legacy_Tests`) to be compatible with the
newer :api:`twisted.trial` unittests in this directory.
"""

from __future__ import print_function
from __future__ import unicode_literals

import binascii
import doctest
import glob
import logging
import os
import warnings

from twisted.python import monkey
from twisted.trial import unittest

from bridgedb.test import legacy_Tests as Tests
from bridgedb.test import deprecated


warnings.filterwarnings('ignore', module="bridgedb\.test\.legacy_Tests")
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

def monkeypatchTests():
    """Monkeypatch the old unittests, replacing new, refactored code with their
    original equivalents from :mod:`bridgedb.test.deprecated`.

    The first patch replaces the newer parsing function,
    :func:`~bridgedb.parse.networkstatus.parseALine`, with the older,
    :func:`deprecated one <bridgedb.test.deprecated.parseORAddressLine>` (the
    old function was previously located at
    ``bridgedb.Bridges.parseORAddressLine``).

    The second patch replaces the new :class:`~bridgedb.parse.addr.PortList`,
    with the :class:`older one <bridgedb.test.deprecated.PortList>` (which
    was previously located at ``bridgedb.Bridges.PortList``).

    The third, forth, and fifth monkeypatches add some module-level attributes
    back into :mod:`bridgedb.Bridges`.

    :rtype: :api:`~twisted.python.monkey.MonkeyPatcher`
    :returns: A :api:`~twisted.python.monkey.MonkeyPatcher`, preloaded with
              patches from :mod:`bridgedb.test.deprecated`.
    """
    patcher = monkey.MonkeyPatcher()
    patcher.addPatch(Tests.networkstatus, 'parseALine',
                     deprecated.parseORAddressLine)
    patcher.addPatch(Tests.addr, 'PortList', deprecated.PortList)
    patcher.addPatch(Tests.bridgedb.Bridges, 'PORTSPEC_LEN', 16)
    patcher.addPatch(Tests.bridgedb.Bridges, 're_ipv4', deprecated.re_ipv4)
    patcher.addPatch(Tests.bridgedb.Bridges, 're_ipv6', deprecated.re_ipv6)
    patcher.addPatch(Tests.bridgedb.Bridges, 'HEX_FP_LEN', 40)
    patcher.addPatch(Tests.bridgedb.Bridges, 'toHex', binascii.b2a_hex)
    patcher.addPatch(Tests.bridgedb.Bridges, 'fromHex', binascii.a2b_hex)
    patcher.addPatch(Tests.bridgedb.Bridges, 'is_valid_fingerprint',
                     deprecated.is_valid_fingerprint)
    patcher.addPatch(Tests.bridgedb.Bridges, 'PluggableTransport',
                     deprecated.PluggableTransport)
    patcher.addPatch(Tests.bridgedb.Bridges, 'Bridge',
                     deprecated.Bridge)
    return patcher


class DynamicTestCaseMeta(type):
    """You know how scary the seemingly-arbitrary constants in elliptic curve
    cryptography seem? Well, I am over nine thousand times more scary. Dynamic
    warez… beware! Be afraid; be very afraid.

    :ivar testResult: An :class:`unittest.TestResult` adapted with
                      :api:`twisted.trial.unittest.PyUnitResultAdapter`, for
                      storing test failures and successes in.

    A base class which uses this metaclass should define the following class
    attributes:

    :ivar testSuites: A list of :class:`unittest.TestSuite`s (or their
                      :mod:`doctest` or :api:`twisted.trial` equivalents).
    :ivar methodPrefix: A string to prefix the generated method names
                        with. (default: 'test_')
    """

    testResult = unittest.PyUnitResultAdapter(pyunit.TestResult())

    def __new__(cls, name, bases, attrs):
        """Construct the initialiser for a new
        :api:`twisted.trial.unittest.TestCase`.
        """
        logging.debug("Metaclass __new__ constructor called for %r" % name)

        if not 'testSuites' in attrs:
            attrs['testSuites'] = list()
        if not 'methodPrefix' in attrs:
            attrs['methodPrefix'] = 'test_'

        testSuites   = attrs['testSuites']
        methodPrefix = attrs['methodPrefix']
        logging.debug(
            "Metaclass __new__() class %r(testSuites=%r, methodPrefix=%r)" %
            (name, '\n\t'.join([str(ts) for ts in testSuites]), methodPrefix))

        generatedMethods = cls.generateTestMethods(testSuites, methodPrefix)
        attrs.update(generatedMethods)
        #attrs['init'] = cls.__init__  # call the standard initialiser
        return super(DynamicTestCaseMeta, cls).__new__(cls, name, bases, attrs)

    @classmethod
    def generateTestMethods(cls, testSuites, methodPrefix='test_'):
        """Dynamically generate methods and their names for a
        :api:`twisted.trial.unittest.TestCase`.

        :param list testSuites: A list of :class:`unittest.TestSuite`s (or
                                their :mod:`doctest` or :api:`twisted.trial`
                                equivalents).
        :param str methodPrefix: A string to prefix the generated method names
                                 with. (default: 'test_')
        :rtype: dict
        :returns: A dictionary of class attributes whose keys are dynamically
                  generated method names (prefixed with **methodPrefix**), and
                  whose corresponding values are dynamically generated methods
                  (taken out of the class attribute ``testSuites``).
        """
        def testMethodFactory(test, name):
            def createTestMethod(test):
                def testMethod(*args, **kwargs):
                    """When this function is generated, a methodname (beginning
                    with whatever **methodPrefix** was set to) will also be
                    generated, and the (methodname, method) pair will be
                    assigned as attributes of the generated
                    :api:`~twisted.trial.unittest.TestCase`.
                    """
                    # Get the number of failures before test.run():
                    origFails = len(cls.testResult.original.failures)
                    test.run(cls.testResult)
                    # Fail the generated testMethod if the underlying failure
                    # count has increased:
                    if (len(cls.testResult.original.failures) > origFails):
                        fail = cls.testResult.original.failures[origFails:][0]
                        raise unittest.FailTest(''.join([str(fail[0]),
                                                         str(fail[1])]))
                    return cls.testResult
                testMethod.__name__ = str(name)
                return testMethod
            return createTestMethod(test)

        newAttrs = {}
        for testSuite in testSuites:
            for test in testSuite:
                origName = test.id()
                if origName.find('.') > 0:
                    origFunc = origName.split('.')[-2:]
                    origName = '_'.join(origFunc)
                if origName.endswith('_py'):  # this happens with doctests
                    origName = origName.strip('_py')
                methName = str(methodPrefix + origName).replace('.', '_')
                meth = testMethodFactory(test, methName)
                logging.debug("Set %s.%s=%r" % (cls.__name__, methName, meth))
                newAttrs[methName] = meth
        return newAttrs


class OldUnittests(unittest.TestCase):
    """A wrapper around :mod:`bridgedb.Tests` to produce :api:`~twisted.trial`
    compatible output.

    Generates a :api:`twisted.trial.unittest.TestCase` containing a
    test for each of the individual tests in :mod:`bridgedb.Tests`.

    Each test in this :api:`~twisted.trial.unittest.TestCase`` is dynamically
    generated from one of the old unittests in :mod:`bridgedb.Tests`. Then,
    the class is wrapped to cause the results reporting mechanisms to be
    :api:`~twisted.trial` compatible.

    :returns: A :api:`twisted.trial.unittest.TestCase`.
    """
    __metaclass__ = DynamicTestCaseMeta
    testSuites    = Tests.testSuite()
    testResult    = unittest.PyUnitResultAdapter(pyunit.TestResult())
    methodPrefix  = 'test_regressionsNewCode_'


class MonkeypatchedOldUnittests(unittest.TestCase):
    """A wrapper around :mod:`bridgedb.Tests` to produce :api:`~twisted.trial`
    compatible output.

    For each test in this ``TestCase``, one of the old unittests in
    bridgedb/Tests.py is run. For all of the tests, some functions and classes
    are :api:`twisted.python.monkey.MonkeyPatcher.patch`ed with old,
    deprecated code from :mod:`bridgedb.test.deprecated` to ensure that any
    new code has not caused any regressions.
    """
    __metaclass__ = DynamicTestCaseMeta
    testSuites    = Tests.testSuite()
    testResult    = unittest.PyUnitResultAdapter(pyunit.TestResult())
    methodPrefix  = 'test_regressionsOldCode_'
    patcher       = monkeypatchTests()

    def runWithPatches(self, *args):
        """Replaces :api:`~twisted.trial.unittest.TestCase.run` as the default
        methodName to run. This method calls ``run()`` though
        ``self.patcher.runWithPatches``, using the class **testResult** object.
        """
        self.patcher.runWithPatches(self.run, self.testResult)
        self.patcher.restore()

    def __init__(self, methodName='runWithPatches'):
        super(MonkeypatchedOldUnittests, self).__init__(methodName=methodName)


class TrialAdaptedDoctests(unittest.TestCase):
    """Discovers and runs all doctests within the ``bridgedb`` package.

    Finds all doctests from the directory that BridgeDB was installed in, in
    all Python modules and packages, and runs them with :api:`twisted.trial`.
    """
    __metaclass__ = DynamicTestCaseMeta
    testSuites    = generateTrialAdaptedDoctestsSuite()
    testResult    = unittest.PyUnitResultAdapter(pyunit.TestResult())
    methodPrefix  = 'test_doctestsIn_'
