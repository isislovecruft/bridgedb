# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2015, The Tor Project, Inc.
#             (c) 2007-2015, all entities within the AUTHORS file
#             (c) 2013-2015, Isis Lovecruft
# :license: see LICENSE for licensing information

"""Unittests for the :mod:`bridgedb.parse.nickname` module."""

from twisted.trial import unittest

from bridgedb.parse.nickname import isValidRouterNickname


class IsValidRouterNicknameTests(unittest.TestCase):
    """Unittests for :func:`bridgedb.parse.nickname.isValidRouterNickname`."""

    def test_parse_nickname_isValidRouterNickname_valid(self):
        """isValidRouterNickname() should return True for a valid nickname."""
        name = 'Unmentionable'
        self.assertTrue(isValidRouterNickname(name))

    def test_parse_nickname_isValidRouterNickname_valid_1(self):
        """isValidRouterNickname() should return True for a valid nickname."""
        name = 'maketotaldestroy'
        self.assertTrue(isValidRouterNickname(name))

    def test_parse_nickname_isValidRouterNickname_invalid_symbols(self):
        """isValidRouterNickname() should return False for an invalid nickname
        (with symbols in it).
        """
        name = 'what_the_bl#@p?!'
        self.assertFalse(isValidRouterNickname(name))

    def test_parse_nickname_isValidRouterNickname_invalid_too_long(self):
        """isValidRouterNickname() should return False for an invalid nickname
        (too long).
        """
        name = 'ThisIsReallyMoreOfANovellaRatherThanAnOnionRouterNickname'
        self.assertFalse(isValidRouterNickname(name))

    def test_parse_nickname_isValidRouterNickname_invalid_too_short(self):
        """isValidRouterNickname() should return False for an invalid nickname
        (empty string).
        """
        name = ''
        self.assertFalse(isValidRouterNickname(name))

    def test_parse_nickname_isValidRouterNickname_invalid_None(self):
        """isValidRouterNickname(None) should return False."""
        name = None
        self.assertFalse(isValidRouterNickname(name))

    def test_parse_nickname_isValidRouterNickname_invalid_spaces(self):
        """isValidRouterNickname() should return False for an invalid nickname
        (contains spaces).
        """
        name = 'As you wish'
        self.assertFalse(isValidRouterNickname(name))
