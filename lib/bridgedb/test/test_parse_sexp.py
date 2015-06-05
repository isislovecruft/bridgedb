# -*- coding: utf-8  -*-
# ____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013-2015, Isis Lovecruft
#             (c) 2007-2015, The Tor Project, Inc.
# :license: see LICENSE for licensing information
# ____________________________________________________________________________

"""Unittests for :mod:`bridgedb.parse.sexp`."""

from __future__ import print_function

import logging

from twisted.trial import unittest

from bridgedb.hashring import Hashring
from bridgedb.parse import sexp


class SexpTests(unittest.TestCase):
    def setUp(self):
        self.thisIsASexp = "(1 2 3 4)"
        self.thisIsANestedSexp = "(1 (2 (3 (4))))"
        self.thisIsNotASexp = "this is not a sexp"
        self.thisIsAList = [1, 2, 3, 4]
        self.thisIsANestedList = [1, [2, [3, [4]]]]
        self.thisIsSomethingElse = Hashring('key')

    def test_isSexp_sexp(self):
        self.assertTrue(sexp.isSexp(self.thisIsASexp))

    def test_isSexp_nested_sexp(self):
        self.assertTrue(sexp.isSexp(self.thisIsANestedSexp))

    def test_isSexp_not_sexp(self):
        self.assertFalse(sexp.isSexp(self.thisIsNotASexp))

    def test_isSexp_list(self):
        self.assertFalse(sexp.isSexp(self.thisIsAList))

    def test_isSexp_nested_list(self):
        self.assertFalse(sexp.isSexp(self.thisIsANestedList))

    def test_fromSexp_sexp(self):
        self.assertEqual(sexp.fromSexp(self.thisIsASexp),
                         self.thisIsAList)

    def test_fromSexp_nested_sexp(self):
        self.assertEqual(sexp.fromSexp(self.thisIsANestedSexp),
                         self.thisIsANestedList)

    def test_fromSexp_not_sexp(self):
        self.assertRaises(sexp.SexpressionError,
                          sexp.fromSexp, self.thisIsNotASexp)

    def test_fromSexp_list(self):
        self.assertEqual(sexp.fromSexp(self.thisIsAList),
                         self.thisIsAList)

    def test_fromSexp_nested_list(self):
        self.assertEqual(sexp.fromSexp(self.thisIsANestedList),
                         self.thisIsANestedList)

    def test_fromSexp_something_else(self):
        self.assertRaises(sexp.SexpressionError,
                          sexp.fromSexp, self.thisIsSomethingElse)

    def test_toSexp_sexp(self):
        self.assertEqual(sexp.toSexp(self.thisIsASexp),
                         self.thisIsASexp)

    def test_toSexp_nested_sexp(self):
        self.assertEqual(sexp.toSexp(self.thisIsANestedSexp),
                         self.thisIsANestedSexp)

    def test_toSexp_not_sexp(self):
        self.assertRaises(sexp.SexpressionError,
                          sexp.toSexp, self.thisIsNotASexp)

    def test_toSexp_list(self):
        self.assertEqual(sexp.toSexp(self.thisIsAList),
                         self.thisIsASexp)

    def test_toSexp_nested_list(self):
        self.assertEqual(sexp.toSexp(self.thisIsANestedList),
                         self.thisIsANestedSexp)

    def test_toSexp_something_else(self):
        self.assertRaises(sexp.SexpressionError,
                          sexp.toSexp, self.thisIsSomethingElse)
