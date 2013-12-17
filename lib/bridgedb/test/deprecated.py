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

"""deprecated ― functions and classes which have been removed from the
production code but are kept in order to be used in regression testing.
"""

import ipaddr
import re

from twisted.python import deprecate
from twisted.python.versions import Version


PORTSPEC_LENGTH = 16

re_ipv6 = re.compile("\[([a-fA-F0-9:]+)\]:(.*$)")
re_ipv4 = re.compile("((?:\d{1,3}\.?){4}):(.*$)")

deprecate.deprecatedModuleAttribute(
    Version('bridgedb', 0, 0, 1),
    "Removed due to 'bridgedb.Bridges.PortList' being moved to "\
    "'bridgedb.parse.addr.PortList.",
    "bridgedb.Bridges",
    "PORTSPEC_LENGTH")

deprecate.deprecatedModuleAttribute(
    Version('bridgedb', 0, 0, 1),
    "Attribute 'bridgedb.Bridges.re_ipv4' was removed due to "\
    "'bridgedb.Bridges.parseORAddressLine' moving to "\
    "'bridgedb.parse.networkstatus.",
    "bridgedb.Bridges",
    "re_ipv4")

deprecate.deprecatedModuleAttribute(
    Version('bridgedb', 0, 0, 1),
    "Attribute 'bridgedb.Bridges.re_ipv6' was removed due to "\
    "'bridgedb.Bridges.parseORAddressLine' moving to "\
    "'bridgedb.parse.networkstatus.",
    "bridgedb.Bridges",
    "re_ipv6")


@deprecate.deprecated(
    Version('bridgedb', 0, 0, 1),
    replacement='bridgedb.parse.networkstatus.parseALine')
def parseORAddressLine(line):
    """Deprecated :func:`bridgedb.Bridges.parseORAddressLine`, removed in
    bridgedb-0.1.0, in commit 1f111e5.

    This function and the newer parsers from :mod:`bridgedb.parse.netstatus`
    are alternately :meth:`~twisted.python.monkey.MonkeyPatcher.patch`ed into
    the :mod:`old unittests <bridgedb.Tests>`, so that the later functions as
    a suite of regression tests.
    """
    address = None
    portlist = None
    # try regexp to discover ip version
    for regex in [re_ipv4, re_ipv6]:
        m = regex.match(line)
        if m:
            # get an address and portspec, or raise ParseError
            try:
                address  = ipaddr.IPAddress(m.group(1))
                portlist = PortList(m.group(2))
            except (IndexError, ValueError): raise ParseORAddressError(line)

    # return a valid address, portlist or raise ParseORAddressError
    if address and portlist and len(portlist): return address,portlist
    raise ParseORAddressError(line)


@deprecate.deprecated(
    Version('bridgedb', 0, 0, 1),
    replacement='bridgedb.parse.networkstatus.NetworkstatusParsingError')
class ParseORAddressError(Exception):
    def __init__(self, line=None):
        msg = "Invalid or-address line"
        if line:
            msg += ": {0}".format(line)
        Exception.__init__(self, msg)


@deprecate.deprecated(
    Version('bridgedb', 0, 0, 1),
    replacement='bridgedb.parse.addr.PortList')
class PortList:
    """Deprecated :class:`bridgedb.Bridges.PortList`, replaced in
    bridgedb-0.1.0, in commit 1f111e5, by
    :class:`bridgedb.parse.addr.PortList`.

    This class and the newer class from :mod:`bridgedb.parse.addr` are
    alternately :meth:`~twisted.python.monkey.MonkeyPatcher.patch`ed into the
    :mod:`old unittests <bridgedb.Tests>`, so that the later functions as a
    suite of regression tests.
    """
    def __init__(self, *args, **kwargs):
        self.ports = set()
        self.add(*args)

    def _sanitycheck(self, val):
        #XXX: if debug=False this is disabled. bad!
        assert type(val) is int
        assert(0 < val <= 65535)

    def __contains__(self, val1):
        return val1 in self.ports

    def add(self, *args):
        PORTSPEC_LEN = 16
        for arg in args:
            try:
                if type(arg) is str:
                    ports = set([int(p) for p in arg.split(',')][:PORTSPEC_LEN])
                    [self._sanitycheck(p) for p in ports]
                    self.ports.update(ports)
                if type(arg) is int:
                    self._sanitycheck(arg)
                    self.ports.update([arg])
                if type(arg) is PortList:
                    self.add(list(arg.ports))
            except AssertionError: raise ValueError
            except ValueError: raise

    def __iter__(self):
        return self.ports.__iter__()

    def __str__(self):
        s = ""
        for p in self.ports:
            s += "".join(",%s"%p)
        return s.lstrip(",")

    def __repr__(self):
        return "PortList('%s')" % self.__str__()

    def __len__(self):
        return len(self.ports)

    def __getitem__(self, x):
        return list(self.ports)[x]
