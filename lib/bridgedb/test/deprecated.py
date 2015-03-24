# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013-2015, Isis Lovecruft
#             (c) 2007-2015, The Tor Project, Inc.
#             (c) 2007-2015, all entities within the AUTHORS file
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

@deprecate.deprecated(Version('bridgedb', 0, 2, 4),
                      replacement='bridgedb.parse.descriptors.parseExtraInfoFiles')
def parseExtraInfoFile(f):
    """
    parses lines in Bridges extra-info documents.
    returns an object whose type corresponds to the
    relevant set of extra-info lines.

    presently supported lines and the accompanying type are:

        { 'transport': PluggableTransport, }

    'transport' lines (torspec.git/proposals/180-pluggable-transport.txt)

        Bridges put the 'transport' lines in their extra-info documents.
        the format is:

            transport SP <methodname> SP <address:port> [SP arglist] NL
    """

    ID = None
    for line in f:
        line = line.strip()

        argdict = {}

        # do we need to skip 'opt' here?
        # if line.startswith("opt "):
        #     line = line[4:]

        # get the bridge ID ?
        if line.startswith("extra-info "): #XXX: get the router ID
            line = line[11:]
            (nickname, ID) = line.split()
            logging.debug("  Parsed Nickname: %s", nickname)
            if isValidFingerprint(ID):
                logging.debug("  Parsed fingerprint: %s", ID)
                ID = fromHex(ID)
            else:
                logging.debug("  Parsed invalid fingerprint: %s", ID)

        # get the transport line
        if ID and line.startswith("transport "):
            fields = line[10:].split()

            if len(fields) >= 3:
                argdict = {}
                # PT argumentss are comma-separated in the extrainfo
                # descriptors. While there *shouldn't* be anything after them
                # that was separated by a space (and hence would wind up being
                # in a different `field`), if there was we'll join it to the
                # rest of the PT arguments with a comma so that they are
                # parsed as if they were PT arguments as well:
                allargs = ','.join(fields[2:])
                for arg in allargs.split(','):
                    try:
                        k, v = arg.split('=')
                    except ValueError:
                        logging.warn("  Couldn't parse K=V from PT arg: %r" % arg)
                    else:
                        logging.debug("  Parsed PT Argument: %s: %s" % (k, v))
                        argdict[k] = v

            # get the required fields, method name and address
            if len(fields) >= 2:
                # get the method name
                # Method names must be C identifiers
                for regex in [re_ipv4, re_ipv6]:
                    try:
                        method_name = re.match('[_a-zA-Z][_a-zA-Z0-9]*',fields[0]).group()
                        m = regex.match(fields[1])
                        address  = ipaddr.IPAddress(m.group(1))
                        port = int(m.group(2))
                        logging.debug("  Parsed Transport: %s %s:%d"
                                      % (method_name, address, port))
                        yield ID, method_name, address, port, argdict
                    except (IndexError, ValueError, AttributeError):
                        # skip this line
                        continue

        # end of descriptor is defined how?
        if ID and line.startswith("router-signature"):
            ID = None

@deprecate.deprecated(Version('bridgedb', 0, 2, 4),
                      replacement='bridgedb.parse.descriptors.parseNetworkStatusFile')
def parseStatusFile(networkstatusFile):
    """Parse entries in a bridge networkstatus file.

    :type networkstatusFile: A file-like object.
    :param networkstatusFile: A file containing `@type bridge-networkstatus` documents.
    """
    (nickname, ID, descDigest, timestamp,
     ORaddr, ORport, dirport, addr, portlist) = (None for x in xrange(9))
    running = stable = False
    parsedORAddressLines = 0
    or_addresses = {}

    for line in networkstatusFile:
        line = line.strip()
        if line.startswith("opt "):
            line = line[4:]

        if line.startswith("r "):
            (nickname, ID, descDigest, timestamp,
             ORaddr, ORport, dirport) = networkstatus.parseRLine(line)
            hexID = toHex(ID)
            logging.debug("Parsed networkstatus line:")
            logging.debug("  Nickname:   %s" % nickname)
            logging.debug("  Identity:   %s" % hexID)
            if descDigest:
                descDigest = toHex(descDigest)
                logging.debug("  Descriptor: {0}".format(descDigest))
                logging.debug("  Timestamp:  {0}".format(timestamp))
                logging.debug("  ORAddress:  {0}".format(ORaddr))
                logging.debug("  ORport:     {0}".format(ORport))
                logging.debug("  dirport:    {0}".format(dirport))

        elif ID and line.startswith("a "):
            try:
                addr, portlist = networkstatus.parseALine(line, toHex(ID))
            except networkstatus.NetworkstatusParsingError as error:
                logging.error(error)
            else:
                if (addr is not None) and (portlist is not None):
                    try:
                        or_addresses[addr].add(portlist)
                    except (KeyError, AttributeError):
                        or_addresses[addr] = portlist
                    parsedORAddressLines += 1

        elif ID and timestamp and line.startswith("s "):
            running, stable = networkstatus.parseSLine(line)
            logging.debug("Bridges.parseStatusFile(): "
                          "yielding %s nickname=%s descDigest=%s "
                          "running=%s stable=%s oraddr=%s orport=%s "
                          "oraddrs=%s ts=%s"
                          % (hexID, nickname, descDigest, running,
                             stable, ORaddr, ORport, or_addresses,
                             timestamp))
            yield (ID, nickname, descDigest, running, stable,
                   ipaddr.IPAddress(ORaddr), ORport,
                   or_addresses, timestamp)

            (nickname, ID, descDigest, timestamp, ORaddr, ORport, dirport,
             addr, portlist, hexID) = (None for x in xrange(10))
            running = stable = False
            or_addresses = {}

    logging.debug("Total ORAddress lines parsed from '%s': %d"
                  % (networkstatusFile.name, parsedORAddressLines))


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
    replacement='bridgedb.bridges.Bridge')
class Bridge(object):
    """Holds information for a single bridge, along with any Pluggable
    Transports it is also running.

    :attr str nickname: The bridge's nickname.  Not currently used.
    :attr ip: (:class:`ipaddr.IPAddress`) The bridge's IPv4 address, specified
        on the 'r'-line in a networkstatus document.
    :attr int orport: The bridge's OR port.
    :attr dict or_addresses: The bridges alternate IP addresses. The keys
        should be instances of ``ipaddr.IPAddress``, and the value should be a
        :class:`bridgedb.parse.addr.PortList` for the port(s) on which that
        address is listening.
    :attr list transports: List of :class:`PluggableTransport` instances for
        each PT which the bridge supports.
    :attr str fingerprint: The bridge's identity digest, in lowercase hex,
        without whitespace.
    :attr bool running: ``True``, if this bridge was given the ``Running`` flag.
    :attr bool stable: ``True``, if this bridge was given the ``Stable`` flag.
    :attr dict blockingCountries: A dictionary whose keys are strings of
        ``"IP:port"`` pairs, and the keys are lists of two letter country
        codes which block that IP:port. For example::
            {"1.2.3.4:9001": ['sk', 'us', 'ir', 'cn']}
    :attr str desc_digest: SHA1 hexdigest of the bridge's descriptor as
        defined in the networkstatus document.
    :attr str ei_digest: SHA1 hexdigest of the bridge's extra-info document as
        given in the bridge's descriptor, corresponding to desc_digest.
    :attr bool verified: Did we receive the descriptor for this bridge that
        was specified in the networkstatus?
    """
    def __init__(self, nickname, ip, orport, fingerprint=None, id_digest=None,
                 or_addresses=None, transports=None):
        """Create a new Bridge. One of fingerprint and id_digest must be set.
        """
        self.nickname = nickname
        self.ip = ip
        self.orport = orport
        if not or_addresses: or_addresses = {}
        self.or_addresses = or_addresses
        if not transports: transports = []
        self.transports = transports
        self.running = self.stable = None
        self.blockingCountries = {}
        self.desc_digest = None
        self.ei_digest = None
        self.verified = False

        if id_digest is not None:
            assert fingerprint is None
            if len(id_digest) != DIGEST_LEN:
                raise TypeError("Bridge with invalid ID")
            self.fingerprint = toHex(id_digest)
        elif fingerprint is not None:
            if not isValidFingerprint(fingerprint):
                raise TypeError("Bridge with invalid fingerprint (%r)"%
                                fingerprint)
            self.fingerprint = fingerprint.lower()
        else:
            raise TypeError("Bridge with no ID")

    def setDescriptorDigest(self, digest):
        """Set the descriptor digest, specified in the NS."""
        self.desc_digest = digest

    def setExtraInfoDigest(self, digest):
        """Set the extra-info digest, specified in the descriptor."""
        self.ei_digest = digest

    def setVerified(self):
        """Call when the bridge's descriptor is parsed"""
        self.verified = True

    def isVerified(self):
        """Returns the truthiness of ``verified``"""
        return self.verified

    def getID(self):
        """Return the bridge's identity digest."""
        return fromHex(self.fingerprint)

    def __repr__(self):
        """Return a piece of python that evaluates to this bridge."""
        if self.or_addresses:
            return "Bridge(%r,%r,%d,%r,or_addresses=%s)"%(
                self.nickname, self.ip, self.orport, self.fingerprint,
                self.or_addresses)
        return "Bridge(%r,%r,%d,%r)"%(
            self.nickname, self.ip, self.orport, self.fingerprint)

    def getConfigLine(self, includeFingerprint=False, addressClass=None,
            request=None, transport=None):
        """Returns a valid bridge line for inclusion in a torrc.

        :param bool includeFingerprint: If ``True``, include the
            ``fingerprint`` of this :class:`Bridge` in the returned bridge
            line.
        :param DOCDOC addressClass: Type of address to choose.
        :param str request: A string unique to this request e.g. email-address
            or ``uniformMap(ip)`` or ``'default'``.
        :param str transport: A pluggable transport method name.
        """

        if not request: request = 'default'
        digest = getHMACFunc('Order-Or-Addresses')(request)
        pos = long(digest[:8], 16) # lower 8 bytes -> long

        # default address type
        if not addressClass: addressClass = ipaddr.IPv4Address

        # pluggable transports
        if transport:
            # filter by 'methodname'
            transports = filter(lambda x: transport == x.methodname,
                    self.transports)
            # filter by 'addressClass'
            transports = filter(lambda x: isinstance(x.address, addressClass),
                    transports)
            if transports:
                pt = transports[pos % len(transports)]
                return pt.getTransportLine(includeFingerprint)

        # filter addresses by address class
        addresses = filter(lambda x: isinstance(x[0], addressClass),
                self.or_addresses.items())

        # default ip, orport should get a chance at being selected
        if isinstance(self.ip, addressClass):
            addresses.insert(0,(self.ip, addr.PortList(self.orport)))

        if addresses:
            address,portlist = addresses[pos % len(addresses)]
            if isinstance(address, ipaddr.IPv6Address): ip = "[%s]"%address
            else: ip = "%s"%address
            orport = portlist[pos % len(portlist)]

            if includeFingerprint:
                return "%s:%d %s" % (ip, orport, self.fingerprint)
            else:
                return "%s:%d" % (ip, orport)

    def getAllConfigLines(self,includeFingerprint=False):
        """Generator. Iterate over all valid config lines for this bridge."""
        for address,portlist in self.or_addresses.items():
            if type(address) is ipaddr.IPv6Address:
                ip = "[%s]" % address
            else:
                ip = "%s" % address

            for orport in portlist:
                if includeFingerprint:
                    yield "bridge %s:%d %s" % (ip,orport,self.fingerprint)
                else:
                    yield "bridge %s:%d" % (ip,orport)
        for pt in self.transports:
            yield pt.getTransportLine(includeFingerprints)


    def assertOK(self):
        assert is_valid_ip(self.ip)
        assert isValidFingerprint(self.fingerprint)
        assert 1 <= self.orport <= 65535
        if self.or_addresses:
            for address, portlist in self.or_addresses.items():
                assert is_valid_ip(address)
                for port in portlist:
                    assert type(port) is int
                    assert 1 <= port <= 65535

    def setStatus(self, running=None, stable=None):
        if running is not None:
            self.running = running
        if stable is not None:
            self.stable = stable

    def isBlocked(self, countryCode, addressClass, methodname=None):
        """ if at least one address:port of the selected addressClass and
        (optional) transport type is not blocked in countryCode, return True
        """
        # 1) transport is specified
        if methodname is not None:
            for transport in self.transports:
                key = "%s:%s" % (transport.address, transport.port)
                if (isinstance(transport.address, addressClass)
                        and transport.methodname.lower() == methodname.lower()):
                    try:
                        if countryCode not in self.blockingCountries[key]:
                            return False
                    except KeyError:
                        return False # no blocklist
            return True
        # 2) no transport specified (default)
        else:
            # 3) check primary ip, port
            # XXX: could be more elegant if ip,orport were not special case
            if isinstance(self.ip, addressClass):
                key = "%s:%s" % (self.ip, self.orport)
                try:
                    if countryCode not in self.blockingCountries[key]:
                        return False
                except KeyError: return False # no blocklist

            # 4) check or addresses
            for address,portlist in self.or_addresses.items():
                if isinstance(address, addressClass):
                    # check each port
                    for port in portlist:
                        key = "%s:%s" % (address, port)
                        try:
                            if countryCode not in self.blockingCountries[key]:
                                return False
                        except KeyError: return False # no blocklist
            return True

    # Bridge Stability (#5482) properties.
    @property
    def familiar(self):
        """
        A bridge is 'familiar' if 1/8 of all active bridges have appeared
        more recently than it, or if it has been around for a Weighted Time of 8 days.
        """
        with bridgedb.Storage.getDB() as db:
            return db.getBridgeHistory(self.fingerprint).familiar

    @property
    def wfu(self):
        """Weighted Fractional Uptime"""
        with bridgedb.Storage.getDB() as db:
            return db.getBridgeHistory(self.fingerprint).weightedFractionalUptime

    @property
    def weightedTime(self):
        """Weighted Time"""
        with bridgedb.Storage.getDB() as db:
            return db.getBridgeHistory(self.fingerprint).weightedTime

    @property
    def wmtbac(self):
        """Weighted Mean Time Between Address Change"""
        with bridgedb.Storage.getDB() as db:
            return db.getBridgeHistory(self.fingerprint).wmtbac

    @property
    def tosa(self):
        """the Time On Same Address (TOSA)"""
        with bridgedb.Storage.getDB() as db:
            return db.getBridgeHistory(self.fingerprint).tosa

    @property
    def weightedUptime(self):
        """Weighted Uptime"""
        with bridgedb.Storage.getDB() as db:
            return db.getBridgeHistory(self.fingerprint).weightedUptime


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
