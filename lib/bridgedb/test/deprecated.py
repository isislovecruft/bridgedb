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

deprecate.deprecatedModuleAttribute(
    Version('bridgedb', 0, 2, 3),
    ("Removed due to 'bridgedb.Bridges.HEX_FP_LEN' being moved to "
     "'bridgedb.parse.fingerprint.HEX_FINGERPRINT_LEN."),
    "bridgedb.Bridges", "HEX_FP_LEN")

deprecate.deprecatedModuleAttribute(
    Version('bridgedb', 0, 2, 3),
    ("Removed due to 'bridgedb.Bridges.toHex' being moved to "
     "'bridgedb.parse.fingerprint.toHex."),
    "bridgedb.Bridges", "toHex")

deprecate.deprecatedModuleAttribute(
    Version('bridgedb', 0, 2, 3),
    ("Removed due to 'bridgedb.Bridges.fromHex' being moved to "
     "'bridgedb.parse.fingerprint.fromHex."),
    "bridgedb.Bridges", "fromHex")


@deprecate.deprecated(
    Version('bridgedb', 0, 0, 1),
    replacement='bridgedb.parse.networkstatus.parseALine')
def parseORAddressLine(line):
    """Deprecated :func:`bridgedb.Bridges.parseORAddressLine`, removed in
    bridgedb-0.1.0, in commit 1f111e5.

    This function and the newer parsers from :mod:`bridgedb.parse.netstatus`
    are alternately :api:`~twisted.python.monkey.MonkeyPatcher.patch`ed into
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

@deprecate.deprecated(Version('bridgedb', 0, 2, 3),
                      replacement='bridgedb.parse.fingerprint.isValidFingerprint')
def is_valid_fingerprint(fp):
    """Return true iff fp in the right format to be a hex fingerprint
       of a Tor server.
    """
    if len(fp) != HEX_FP_LEN:
        return False
    try:
        fromHex(fp)
    except TypeError:
        return False
    else:
        return True


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
    Version('bridgedb', 0, 2, 4),
    replacement='bridgedb.bridges.PluggableTransport')
class PluggableTransport(object):
    """A PT with reference to the parent bridge on which it is running.

    Deprecated :class:`bridgedb.Bridges.PluggableTransport`, replaced in
    bridgedb-0.2.4, by :class:`bridgedb.bridges.PluggableTransport`.
    """

    def __init__(self, bridge, methodname, address, port, argdict=None):
        """Create a ``PluggableTransport`` describing a PT running on a bridge.

        Pluggable transports are described within a bridge's ``@type
        bridge-extrainfo`` descriptor, see the ``Specifications: Client
        behavior`` section and the ``TOR_PT_SERVER_TRANSPORT_OPTIONS``
        description in pt-spec.txt_ for additional specification.

        :type bridge: :class:`Bridge`
        :param bridge: The parent bridge running this pluggable transport
            instance, i.e. the main ORPort bridge whose
            ``@type bridge-server-descriptor`` contains a hash digest for a
            ``@type bridge-extrainfo-document``, the latter of which contains
            the parameter of this pluggable transport in its ``transport``
            line.

        :param str methodname: The canonical "name" for this pluggable
            transport, i.e. the one which would be specified in a torrc
            file. For example, ``"obfs2"``, ``"obfs3"``, ``"scramblesuit"``
            would all be pluggable transport method names.

        :param str address: The IP address of the transport. Currently (as of
            20 March 2014), there are no known, widely-deployed pluggable
            transports which support IPv6. Ergo, this is very likely going to
            be an IPv4 address.

        :param int port: A integer specifying the port which this pluggable
            transport is listening on. (This should likely be whatever port the
            bridge specified in its ``ServerTransportPlugin`` torrc line,
            unless the pluggable transport is running in "managed" mode.)

        :param dict argdict: Some PTs can take additional arguments, which
            must be distributed to the client out-of-band. These are present
            in the ``@type bridge-extrainfo-document``, in the ``transport``
            line like so::

                METHOD SP ADDR ":" PORT SP [K=V[,K=V[,K=V[…]]]]

            where K is the **argdict** key, and V is the value. For example,
            in the case of ``scramblesuit``, for which the client must supply
            a shared secret to the ``scramblesuit`` instance running on the
            bridge, the **argdict** would be something like::

                {'password': 'NEQGQYLUMUQGK5TFOJ4XI2DJNZTS4LRO'}

        .. _pt-spec.txt:
             https://gitweb.torproject.org/torspec.git/blob/HEAD:/pt-spec.txt
        """
        #XXX: assert are disabled with python -O
        assert isinstance(bridge, Bridge)
        assert type(address) in (ipaddr.IPv4Address, ipaddr.IPv6Address)
        assert type(port) is int
        assert (0 < port < 65536)
        assert type(methodname) is str

        self.bridge = bridge
        self.address = address
        self.port = port
        self.methodname = methodname
        if type(argdict) is dict:
            self.argdict = argdict
        else: self.argdict = {}

    def getTransportLine(self, includeFingerprint=False, bridgePrefix=False):
        """Get a torrc line for this pluggable transport.

        This method does not return lines which are prefixed with the word
        'bridge', as they would be in a torrc file. Instead, lines returned
        look like this:

        obfs3 245.102.100.252:23619 59ca743e89b508e16b8c7c6d2290efdfd14eea98

        :param bool includeFingerprints: If ``True``, include the digest of
            this bridges public identity key in the torrc line.
        :param bool bridgePrefix: If ``True``, add ``'Bridge '`` to the
             beginning of each returned line (suitable for pasting directly
             into a torrc file).
        :rtype: str
        :returns: A configuration line for adding this pluggable transport
            into a torrc file.
        """
        sections = []

        if bridgePrefix:
            sections.append('Bridge')

        if isinstance(self.address, ipaddr.IPv6Address):
            host = "%s [%s]:%d" % (self.methodname, self.address, self.port)
        else:
            host = "%s %s:%d" % (self.methodname, self.address, self.port)
        sections.append(host)

        if includeFingerprint:
            sections.append(self.bridge.fingerprint)

        args = " ".join(["%s=%s" % (k, v) for k, v in self.argdict.items()])
        sections.append(args)

        line = ' '.join(sections)
        return line


@deprecate.deprecated(
    Version('bridgedb', 0, 0, 1),
    replacement='bridgedb.parse.addr.PortList')
class PortList:
    """Deprecated :class:`bridgedb.Bridges.PortList`, replaced in
    bridgedb-0.1.0, in commit 1f111e5, by
    :class:`bridgedb.parse.addr.PortList`.

    This class and the newer class from :mod:`bridgedb.parse.addr` are
    alternately :api:`~twisted.python.monkey.MonkeyPatcher.patch`ed into the
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
