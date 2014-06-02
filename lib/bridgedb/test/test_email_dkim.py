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

"""Unittests for the :mod:`bridgedb.email.dkim` module."""

import io

from twisted.mail.smtp import rfc822
from twisted.trial import unittest

from bridgedb.email import dkim


class CheckDKIMTests(unittest.TestCase):
    """Tests for :func:`email.server.checkDKIM`."""

    def setUp(self):
        """Create fake email, distributor, and associated context data."""
        self.goodMessage = io.StringIO(unicode("""\
From: user@gmail.com
To: bridges@localhost
X-DKIM-Authentication-Results: pass
Subject: testing

get bridges
"""))
        self.badMessage = io.StringIO(unicode("""\
From: user@gmail.com
To: bridges@localhost
Subject: testing

get bridges
"""))
        self.domainRules = {
            'gmail.com': ["ignore_dots", "dkim"],
            'example.com': [],
            'localhost': [],
        }

    def test_checkDKIM_good(self):
        message = rfc822.Message(self.goodMessage)
        result = dkim.checkDKIM(message,
                                self.domainRules.get("gmail.com"))
        self.assertTrue(result)
                                         

    def test_checkDKIM_bad(self):
        message = rfc822.Message(self.badMessage)
        result = dkim.checkDKIM(message,
                                self.domainRules.get("gmail.com"))
        self.assertIs(result, False)
