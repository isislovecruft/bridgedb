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
from __future__ import unicode_literals

import binascii

from twisted.python import log
from twisted.trial import unittest
from bridgedb.parse import networkstatus

import sure
from sure import this, these, those, the, it


logFormat  = "%(created)d [%(levelname)s] %(module)s.%(funcName)s(): "
logFormat += "%(message)s"
networkstatus.logging.basicConfig(
    filename='test_parse_networkstatus.log',
    level=networkstatus.logging.DEBUG,
    flags='w', format=logFormat)


class ParseNetworkStatusRLineTests(unittest.TestCase):
    """Tests for :func:`bridgedb.parse.networkstatus.parseRLine`.

    The documentation for all class variables, e.g. 'pre' or 'ident', refers
    to what said value should be in a *valid* descriptor.
    """
    #: The prefix for the 'r'-line. Should be an 'r', unless testing that
    #: lines with unknown prefixes are dropped.
    pre   = 'r '
    #: An OR nickname string. To be valid, it should be 1-19 alphanumeric
    #: upper or lower cased characters.
    nick  = 'Testing'
    #: A base64-encoded, SHA-1 digest of the DER-formatted, ASN.1-encoded,
    #: public portion of an OR identity key, with any trailing base64 padding
    #: (any '=' characters) removed.
    ident = 'bXw2N1K9AAKR5undPaTgNUySNxI'
    #: A base64-encoded, SHA-1 digest of the OR
    #: `@type-[bridge-]server-descriptor` document (the whole thing, up until
    #: the 'router signature' line, but not including the signature thereafter),
    #: with any trailing base64 padding (any '=' characters) removed.
    desc  = 'Z6cisoPT9s6hEd4JkHFAlIWAwXQ'
    #: An ISO-8661 formatted timestamp, with a space separator (rather than a
    #: 'T' character).
    ts    = '2013-10-31 15:15:15'
    #: An IPv4 address.
    ip    = '221.251.0.42'
    #: An ORPort number.
    port  = '9001'
    #: A DirPort number.
    dirp  = '0'

    def makeRLine(self, *args, **kwargs):
        """Concatenate parameters into an 'r'-line and store the result as
        ``self.line``.

        To create an invalid networkstatus 'r'-line, for example with an
        invalid IP address, use me like this:

        >>> makeRLine(ip='0.0.0.0')

        :keywords: The keyword arguments may be any of the class variables,
            i.e. 'nick' or 'ident', and the variables should be similar to the
            defaults in the class variables. If not given as parameters, the
            class variables will be used.
        """
        line = []
        for kw in ('pre', 'nick', 'ident', 'desc', 'ts', 'ip', 'port', 'dirp'):
            if kw in kwargs.keys():
                if kwargs[kw]:
                    line.append(kwargs[kw])
                elif kwargs[kw] is False:
                    pass
            else:
                line.append(getattr(self, kw, ''))

        self.line = ' '.join([l for l in line]).strip()
        log.msg("\n  Testing networkstatusline:\n    %r..." % self.line)
        self.assertTrue(self.line != '')

    def tearDown(self):
        self.line = ''

    def assertAllFieldsAreNone(self, fields):
        """Assert that every field in the iterable ``fields`` is None."""
        for field in fields:
            self.assertTrue(field is None)

    def test_missingPrefix(self):
        """Test a networkstatus 'r'-line that is missing the 'r ' prefix."""
        self.makeRLine(pre=False)
        fields = networkstatus.parseRLine(self.line)
        self.assertAllFieldsAreNone(fields)

    def test_wrongNumberOfFields(self):
        """Test a line missing digest, ORPort, and DirPort fields."""
        self.makeRLine(desc=False, port=False, dirp=False)
        fields = networkstatus.parseRLine(self.line)
        self.assertAllFieldsAreNone(fields)

    def test_wrongFieldOrder(self):
        """Test a line with the identity and descriptor digests switched."""
        self.makeRLine(desc=self.ident, ident=self.desc)
        fields = networkstatus.parseRLine(self.line)
        nick, others = fields[0], fields[1:]

        this(nick).should.be.ok
        this(nick).should.be.a(basestring)
        this(nick).should.equal(self.nick)

        the(others).should.be.a(tuple)
        the(others).should.have.length_of(6)
        for other in others:
            the(other).should.be(None)

    def test_invalidNicknameNonAlphanumeric(self):
        """Test a line with a non-alphanumeric router nickname."""
        self.makeRLine(nick='abcdef/*comment*/')
        fields = networkstatus.parseRLine(self.line)
        nick, ident, desc = fields[:3]
        this(nick).should.be(None)
        the(ident).should.be.a(basestring)
        the(desc).should.be(None)

    def test_invalidNicknameTooLong(self):
        """Test a line with a router nickname which is way too long."""
        self.makeRLine(nick='ThisIsAReallyReallyLongRouterNickname')
        fields = networkstatus.parseRLine(self.line)
        nick, ident, desc = fields[:3]
        this(nick).should.be(None)
        the(ident).should.be.a(basestring)
        the(desc).should.be(None)

    def test_invalidIdentBase64(self):
        """Test line with '%$>@,<' for an identity digest."""
        self.makeRLine(ident='%$>#@,<')
        (nick, ident, desc, ts,
         ip, port, dirp) = networkstatus.parseRLine(self.line)

        the(nick).should.be.ok
        the(nick).should.be.a(basestring)
        the(nick).should.equal(self.nick)
        the(ident).should.be(None)
        the(desc).should.be(None)

    def test_invalidIdentSingleQuoteChar(self):
        """Test a line with a single quote character for the identity digest."""
        self.makeRLine(ident=chr(0x27))
        fields = networkstatus.parseRLine(self.line)
        nick, ident, desc = fields[:3]

        the(nick).should.be.ok
        the(nick).should.be.a(basestring)
        the(nick).should.be.equal(str(self.nick))
        the(ident).should.be.equal(None)
        the(desc).should.be.equal(None)

    def test_invalidDescriptorDigest(self):
        """Test an 'r'-line with invalid base64 descriptor digest."""
        self.makeRLine(desc='敃噸襶')
        fields = networkstatus.parseRLine(self.line)
        nick, ident, desc, ts, ip = fields[:5]

        the(nick).should.be.ok
        the(nick).should.be.a(basestring)
        the(nick).should.be.equal(str(self.nick))

        the(ident).should.be.a(basestring)
        the(ident).should.be.equal(self.ident)

        the(desc).should.be.equal(None)
        the(ts).should.be.equal(None)
        the(ip).should.be.equal(None)

    def test_invalidDescriptorDigest_missingBase64padding(self):
        """Test a line with invalid base64 (no padding) descriptor digest."""
        self.makeRLine(desc=self.desc.rstrip('=='))
        fields = networkstatus.parseRLine(self.line)
        nick, ident, desc, ts, ip = fields[:5]

        the(nick).should.be.ok
        the(nick).should.be.a(basestring)
        the(nick).should.be.equal(str(self.nick))

        the(ident).should.be.a(basestring)
        the(ident).should.be.equal(self.ident)

        the(desc).should.be.equal(None)
        the(ts).should.be.equal(None)
        the(ip).should.be.equal(None)

    def test_missingAfterDesc(self):
        """Test a line that has a valid descriptor digest, and is missing
        everything after the descriptor digest, i.e. the timestamp, IP address,
        and DirPort.
        """
        self.makeRLine(nick='missingAfterDesc', ts=False, ip=False, dirp=False)
        fields = networkstatus.parseRLine(self.line)
        self.assertAllFieldsAreNone(fields)

    def test_missingAfterIdent(self):
        """Test a line that and is missing the descriptor digest and
        everything after it, i.e. the timestamp, IP address, and DirPort.
        """
        self.makeRLine(nick='noDesc', desc=False, ts=False,
                       ip=False, dirp=False)
        fields = networkstatus.parseRLine(self.line)
        self.assertAllFieldsAreNone(fields)

    def test_invalidTimestamp(self):
        """Test line with two large integers for the timestamp."""
        self.makeRLine(ts='123456789 987654321')
        fields = networkstatus.parseRLine(self.line)

    def test_invalidTimestampMissingDate(self):
        """Test a line where the timestamp is missing the date portion."""
        self.makeRLine(ts='15:15:15')
        fields = networkstatus.parseRLine(self.line)
        self.assertAllFieldsAreNone(fields)

    def test_invalidIPAddress(self):
        """Test a line with an invalid IP address."""
        self.makeRLine(ip='0.0.0.0')
        fields = networkstatus.parseRLine(self.line)
        nick, ident, desc, ts, ip, port = fields[:6]

        the(nick).should.be.equal(self.nick)

        the(ident).should.be.a(basestring)
        the(ident).should.be.equal(self.ident)

        the(desc).should.be.a(basestring)
        the(b64desc).should.be.equal(self.desc)

        the(ts).should.be.a(float)
        the(ip).should.be(None)


class ParseNetworkStatusALineTests(unittest.TestCase):
    """Tests for :func:`bridgedb.parse.networkstatus.parseALine`.

    The documentation for all class variables, e.g. 'pre' or 'oraddr', refers
    to what said value should be in a *valid* descriptor.
    """
    #: The prefix for the 'a'-line. Should be an 'a', unless testing that
    #: lines with unknown prefixes are dropped.
    pre = 'a '
    #: An ORAddress. As of tor-0.2.5.1-alpha, there is only one and it is an
    #: IPv6 address.
    oraddr = '[b8d:48ae:5185:dad:5c2a:4e75:8394:f5f8]'

    def tearDown(self):
        self.line = ''

    def assertAllFieldsAreNone(self, fields):
        """Assert that every field in the iterable ``fields`` is None."""
        for field in fields:
            self.assertTrue(field is None)

    def test_missingPrefix(self):
        self.line = '%s:1234' % self.oraddr
        fields = networkstatus.parseALine(self.line)
        self.assertAllFieldsAreNone(fields)

    def test_IPv4(self):
        self.line = 'a 48.32.199.45:9001'
        ip, port = networkstatus.parseALine(self.line)
        ip, port = self.assertWarns(
            FutureWarning,
            "Got IPv4 address in networkstatus 'a'-line! "\
            "Networkstatus document format may have changed!",
            networkstatus.__file__,
            networkstatus.parseALine,
            self.line)
        this(ip).should.be.a(basestring)
        this(port).should.be.ok
        this(port).should.be.a(networkstatus.addr.PortList)

    def test_IPv4BadPortSeparator(self):
        self.line = 'a 1.1.1.1 9001'
        fields = networkstatus.parseALine(self.line)
        self.assertAllFieldsAreNone(fields)

    def test_IPv6BadPortlist(self):
        self.line = 'a 23.23.23.23:1111,2222,badportlist'
        ip, port = networkstatus.parseALine(self.line)
        this(ip).should.be.a(basestring)
        this(port).should.be(None)

    def test_IPv4MissingPort(self):
        self.line = 'a 1.1.1.1'
        fields = networkstatus.parseALine(self.line)
        self.assertAllFieldsAreNone(fields)

    def test_IPv4InvalidAddress(self):
        self.line = 'a 127.0.0.1:5555'
        fields = networkstatus.parseALine(self.line)
        self.assertAllFieldsAreNone(fields)

    def test_IPv6BadPortSeparator(self):
        self.line = 'a %s missingcolon' % self.oraddr
        fields = networkstatus.parseALine(self.line)
        self.assertAllFieldsAreNone(fields)

    def test_IPv6BadPortlist(self):
        self.line = 'a %s:1111,2222,badportlist' % self.oraddr
        ip, port = networkstatus.parseALine(self.line)
        this(ip).should.be.a(basestring)
        this(port).should.be(None)

    def test_IPv6(self):
        self.line = 'a %s:6004' % self.oraddr
        ip, port = networkstatus.parseALine(self.line)
        this(ip).should.be.a(basestring)
        this(port).should.be.ok
        this(port).should.be.a(networkstatus.addr.PortList)


class ParseNetworkStatusSLineTests(unittest.TestCase):
    """Tests for :func:`bridgedb.parse.networkstatus.parseSLine`."""

    def tearDown(self):
        """Automatically called after each test_* method to run cleanups."""
        self.line = ''

    def test_missingPrefix(self):
        self.line = 'Stable'
        running, stable = networkstatus.parseSLine(self.line)
        self.assertFalse(running)
        self.assertFalse(stable)

    def test_makeBelieveFlag(self):
        """Test that 's'-parser should ignore a 'MakeBelieve' flag."""
        self.line = 's Stable Running MakeBelieve BadExit'
        running, stable = networkstatus.parseSLine(self.line)
        self.assertTrue(running)
        self.assertTrue(stable)

    def test_noFlags(self):
        """Test that an 's'-line with no flags returns False for everything."""
        self.line = ''
        running, stable = networkstatus.parseSLine(self.line)
        self.assertFalse(running)
        self.assertFalse(stable)
