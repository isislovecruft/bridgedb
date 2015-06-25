# -*- coding: utf-8 -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2014-2015, The Tor Project, Inc.
#             (c) 2014-2015, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""Unittests for :mod:`bridgedb.parse.versions`."""


from __future__ import print_function

from twisted.trial import unittest

from bridgedb.parse import versions


class ParseVersionTests(unittest.TestCase):
    """Unitests for :class:`bridgedb.parse.versions.Version`."""

    def test_Version_with_bad_delimiter(self):
        """Test parsing a version number which uses '-' as a delimiter."""
        self.assertRaises(versions.InvalidVersionStringFormat,
                          versions.Version, '2-6-0', package='tor')

    def test_Version_really_long_version_string(self):
        """Parsing a version number which is way too long should raise
        an IndexError which is ignored.
        """
        v = versions.Version('2.6.0.0.beta', package='tor')
        self.assertEqual(v.prerelease, 'beta')
        self.assertEqual(v.major, 6)

    def test_Version_string(self):
        """Test converting a valid Version object into string form."""
        v = versions.Version('0.2.5.4', package='tor')
        self.assertEqual(v.base(), '0.2.5.4')
