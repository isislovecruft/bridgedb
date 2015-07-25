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

"""Unittests for :mod:`bridgedb.interfaces`."""

from twisted.trial import unittest

from bridgedb import interfaces


class DummyNamedOtherThing(interfaces.Named):
    def __init__(self):
        self.name = "hipster"


class DummyNamedThing(interfaces.Named):
    def __init__(self):
        self.whatever = DummyNamedOtherThing()
        self.name = "original"


class NamedTests(unittest.TestCase):
    """Tests for :class:`bridgedb.interfaces.Named`."""

    def test_Named_init(self):
        """Initializing a Named() object should set its name to ''."""
        named = interfaces.Named()
        self.assertEqual(named.name, '')

    def test_Named_name(self):
        """For a Named object A without any other Named objects which have
        object A as an attribute, should just have its name set to whatever
        it was set to.
        """
        named = DummyNamedOtherThing()
        self.assertEqual(named.name, "hipster")

    def test_Named_with_named_object_for_attribute(self):
        """For a Named object A which has another Named object B as an
        attribute, object A should just have its name set to whatever
        it was set to, and object B should have its name set to object A's
        name plus whatever object B's name was set to.
        """
        named = DummyNamedThing()
        self.assertEqual(named.name, "original")
        self.assertEqual(named.whatever.name, "original hipster")
