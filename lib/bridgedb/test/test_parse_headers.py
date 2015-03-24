# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2014-2015, Isis Lovecruft
#             (c) 2007-2015, The Tor Project, Inc.
#             (c) 2007-2015, all entities within the AUTHORS file
# :license: see LICENSE for licensing information

"""Unittests for the :mod:`bridgedb.parse.headers` module."""

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

from twisted.trial import unittest

from bridgedb.parse import headers


class ParseAcceptLanguageTests(unittest.TestCase):
    """Unittests for :func:`bridgedb.parse.headers.parseAcceptLanguage`."""

    def test_noHeaders(self):
        """No header should return an empty list."""
        header = None
        langs = headers.parseAcceptLanguage(header)
        self.assertIsInstance(langs, list)
        self.assertEqual(len(langs), 0)

    def test_defaultTBBHeader(self):
        """The header 'en-us,en;q=0.5' should return ['en_us', 'en']."""
        header = 'en-us,en;q=0.5'
        langs = headers.parseAcceptLanguage(header)
        self.assertIsInstance(langs, list)
        self.assertEqual(len(langs), 2)
        self.assertEqual(langs[0], 'en_us')
        self.assertEqual(langs[1], 'en')

    def test_addNonLocalizedVariant(self):
        """The header 'en-us,en-gb;q=0.5' should return
        ['en_us', 'en', 'en_gb'].
        """
        header = 'en-us,en-gb;q=0.5'
        langs = headers.parseAcceptLanguage(header)
        self.assertIsInstance(langs, list)
        self.assertEqual(len(langs), 3)
        self.assertEqual(langs[0], 'en_us')
        self.assertEqual(langs[1], 'en')
        self.assertEqual(langs[2], 'en_gb')
