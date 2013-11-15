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

"""Unittests for the :mod:`bridgedb.parse.networkstatus` module.

These tests are meant to ensure that the :mod:`bridgedb.parse.networkstatus`
module is functioning correctly.
"""

from __future__ import print_function

from twisted.trial import unittest
from bridgedb.parse import networkstatus

import sure
from sure import this, these, those, the, it


class ParseNetworkStatusRLineTests(unittest.TestCase):
    """Tests for :func:`bridgedb.parse.networkstatus.parseRLine`."""

    pre   = 'r '
    nick  = 'Testing'
    ident = 'bXw2N1K9AAKR5undPaTgNUySNxI'
    desc  = 'Z6cisoPT9s6hEd4JkHFAlIWAwXQ='
    ts    = '2013-10-31 15:15:15'
    ip    = '221.251.0.42'
    port  = '9001'
    dirp  = '0'

    def test_missingPrefix(self):
        line = ' '.join([self.nick, self.ident, self.desc,
                         self.ts, self.ip, self.port, self.dirp])
        self.assertRaises(networkstatus.NetworkstatusParsingError,
                          networkstatus.parseRLine, line)

    def test_wrongNumberOfFields(self):
        line = ' '.join([self.pre, self.nick, self.ident, self.ts, self.ip])
        self.assertRaises(networkstatus.NetworkstatusParsingError,
                          networkstatus.parseRLine, line)

    def test_wrongFieldOrder(self):
        line = ' '.join([self.pre, self.nick, self.desc, self.ident,
                         self.ts, self.ip, self.port, self.dirp])
        fields = networkstatus.parseRLine(line)
        nick, others = fields[0], fields[1:]

        this(nick).should.be.ok
        this(nick).should.be.a(str)
        this(nick).should.equal(self.nick)

        the(others).should.be.a(tuple)
        the(others).should.have.length_of(6)
        for other in others:
            the(other).should.be(None)

    def test_invalidTimestampMissingDate(self):
        line = ' '.join([self.pre, self.nick, self.ident, self.desc,
                         '15:15:15', self.ip, self.port, self.dirp])
        self.assertRaises(networkstatus.NetworkstatusParsingError,
                          networkstatus.parseRLine, line)

    def test_invalidBase64(self):
        line = ' '.join([self.pre, self.nick, '%$>#@,<', self.desc,
                         self.ts, self.ip, self.port, self.dirp])
        nick, ident, desc, ts, ip, port, dirp = networkstatus.parseRLine(line)

        the(nick).should.be.ok
        the(nick).should.be.a(str)
        the(nick).should.equal(self.nick)

        the(ident).should.be(None)
        the(desc).should.be(None)

    def test_invalidTimestamp(self):
        line = ' '.join([self.pre, self.nick, self.ident, self.desc,
                         '123456789 987654321', self.ip, self.port, self.dirp])
        fields = networkstatus.parseRLine(line)
        
    def test_invalidIPAddress(self):
        line = ' '.join([self.pre, self.nick, self.ident, self.desc,
                         self.ts, '0.0.0.0', self.port, self.dirp])
        fields = networkstatus.parseRLine(line)
        
