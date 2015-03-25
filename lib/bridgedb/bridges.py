# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_bridges -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: please see the AUTHORS file for attributions
# :copyright: (c) 2013-2015, Isis Lovecruft
#             (c) 2007-2015, The Tor Project, Inc.
# :license: see LICENSE for licensing information

"""Classes for manipulating and storing Bridges and their attributes."""

from __future__ import print_function

import base64
import codecs
import hashlib
import ipaddr
import logging
import os
import warnings

from Crypto.Util import asn1
from Crypto.Util.number import bytes_to_long
from Crypto.Util.number import long_to_bytes

import bridgedb.Storage

from bridgedb import geo
from bridgedb import safelog
from bridgedb import bridgerequest
from bridgedb.crypto import removePKCS1Padding
from bridgedb.parse.addr import isIPAddress
from bridgedb.parse.addr import isIPv4
from bridgedb.parse.addr import isIPv6
from bridgedb.parse.addr import isValidIP
from bridgedb.parse.addr import PortList
from bridgedb.parse.fingerprint import isValidFingerprint
from bridgedb.parse.fingerprint import toHex
from bridgedb.parse.fingerprint import fromHex
from bridgedb.parse.nickname import isValidRouterNickname


class PluggableTransportUnavailable(Exception):
    """Raised when a :class:`Bridge` doesn't have the requested
    :class:`PluggableTransport`.
    """

class MalformedBridgeInfo(ValueError):
    """Raised when some information about a bridge appears malformed."""

class MalformedPluggableTransport(MalformedBridgeInfo):
    """Raised when information used to initialise a :class:`PluggableTransport`
    appears malformed.
    """

class InvalidPluggableTransportIP(MalformedBridgeInfo):
    """Raised when a :class:`PluggableTransport` has an invalid address."""

class MissingServerDescriptorDigest(MalformedBridgeInfo):
    """Raised when the hash digest for an ``@type bridge-server-descriptor``
    (which should be in the corresponding ``@type bridge-networkstatus``
    document), was missing.
    """

class ServerDescriptorDigestMismatch(MalformedBridgeInfo):
    """Raised when the digest in an ``@type bridge-networkstatus`` document
    doesn't match the hash digest of the ``@type bridge-server-descriptor``'s
    contents.
    """

class ServerDescriptorWithoutNetworkstatus(MalformedBridgeInfo):
    """Raised when we find a ``@type bridge-server-descriptor`` which was not
    mentioned in the latest ``@type bridge-networkstatus`` document.
    """

class InvalidExtraInfoSignature(MalformedBridgeInfo):
    """Raised if the signature on an ``@type bridge-extrainfo`` is invalid."""


class Flags(object):
    """All the flags which a :class:`Bridge` may have."""

    fast = False
    guard = False
    running = False
    stable = False
    valid = False

    def update(self, flags):
        """Update with **flags** taken from an ``@type networkstatus-bridge``
        's'-line.

        From `dir-spec.txt`_:
          |
          | "s" SP Flags NL
          |
          |    [Exactly once.]
          |
          |    A series of space-separated status flags, in lexical order (as ASCII
          |    byte strings).  Currently documented flags are:
          |
          | [...]
          |      "Fast" if the router is suitable for high-bandwidth circuits.
          |      "Guard" if the router is suitable for use as an entry guard.
          | [...]
          |      "Stable" if the router is suitable for long-lived circuits.
          |      "Running" if the router is currently usable.
          | [...]
          |      "Valid" if the router has been 'validated'.

        .. _dir-spec.txt:
            https://gitweb.torproject.org/torspec.git/blob/7647f6d4d:/dir-spec.txt#l1603

        :param list flags: A list of strings containing each of the flags
            parsed from the 's'-line.
        """
        self.fast = 'Fast' in flags
        self.guard = 'Guard' in flags
        self.running = 'Running' in flags
        self.stable = 'Stable' in flags
        self.valid = 'Valid' in flags

        if not self.running:
            logging.debug("Bridge doesn't have the Running flag.")
        if not self.stable:
            logging.debug("Bridge doesn't have the Stable flag.")


class BridgeAddressBase(object):
    """A base class for describing one of a :class:`Bridge`'s or a
    :class:`PluggableTransport`'s location, including its identity key
    fingerprint and IP address.

    :type fingerprint: str
    :ivar fingerprint: The uppercased, hexadecimal fingerprint of the identity
        key of the parent bridge running this pluggable transport instance,
        i.e. the main ORPort bridge whose ``@type bridge-server-descriptor``
        contains a hash digest for a ``@type bridge-extrainfo-document``, the
        latter of which contains the parameter of this pluggable transport in
        its ``transport`` line.

    :type address: ``ipaddr.IPv4Address`` or ``ipaddr.IPv6Address``
    :ivar address: The IP address of :class:`Bridge` or one of its
        :class:`PluggableTransport`s.

    :type country: str
    :ivar country: The two-letter GeoIP country code of the :ivar:`address`.
    """

    def __init__(self):
        self._fingerprint = None
        self._address = None
        self._country = None

    @property
    def fingerprint(self):
        """Get this Bridge's fingerprint.

        :rtype: str
        :returns: A 40-character hexadecimal formatted string representation
            of the SHA-1 hash digest of the public half of this Bridge's
            identity key.
        """
        return self._fingerprint

    @fingerprint.setter
    def fingerprint(self, value):
        """Set this Bridge's fingerprint to **value**.

        .. info: The purported fingerprint will be checked for specification
            conformity with
            :func:`~bridgedb.parse.fingerprint.isValidFingerprint`.

        :param str value: The fingerprint for this Bridge.
        """
        if value and isValidFingerprint(value):
            self._fingerprint = value.upper()

    @fingerprint.deleter
    def fingerprint(self):
        """Reset this Bridge's fingerprint."""
        self._fingerprint = None

    @property
    def address(self):
        """Get this bridge's address.

        :rtype: :class:`~ipaddr.IPv4Address` or :class:`~ipaddr.IPv6Address`
        :returns: The bridge's address.
        """
        return self._address

    @address.setter
    def address(self, value):
        """Set this Bridge's address.

        :param value: The main ORPort IP address of this bridge.
        """
        if value and isValidIP(value): # XXX only conditionally set _address?
            self._address = isIPAddress(value, compressed=False)

    @address.deleter
    def address(self):
        """Reset this Bridge's address to ``None``."""
        self._address = None

    @property
    def country(self):
        """Get the two-letter GeoIP country code for the :ivar:`address`.

        :rtype: str or ``None``
        :returns: If :ivar:`address` is set, this returns a two-letter country
            code for the geolocated region that :ivar:`address` is within;
            otherwise, returns ``None``.
        """
        if self.address:
            return geo.getCountryCode(self.address)


class PluggableTransport(BridgeAddressBase):
    """A single instance of a Pluggable Transport (PT) offered by a
    :class:`Bridge`.

    Pluggable transports are described within a bridge's
    ``@type bridge-extrainfo`` descriptor, see the
    ``Specifications: Client behavior`` section and the
    ``TOR_PT_SERVER_TRANSPORT_OPTIONS`` description in pt-spec.txt_ for
    additional specification.

    .. _pt-spec.txt:
        https://gitweb.torproject.org/torspec.git/blob/HEAD:/pt-spec.txt

    :type fingerprint: str
    :ivar fingerprint: The uppercased, hexadecimal fingerprint of the identity
        key of the parent bridge running this pluggable transport instance,
        i.e. the main ORPort bridge whose ``@type bridge-server-descriptor``
        contains a hash digest for a ``@type bridge-extrainfo-document``, the
        latter of which contains the parameter of this pluggable transport in
        its ``transport`` line.

    :type methodname: str
    :ivar methodname: The canonical "name" for this pluggable transport,
        i.e. the one which would be specified in a torrc file. For example,
        ``"obfs2"``, ``"obfs3"``, ``"scramblesuit"`` would all be pluggable
        transport method names.

    :type address: ``ipaddr.IPv4Address`` or ``ipaddr.IPv6Address``
    :ivar address: The IP address of the transport. Currently (as of 20 March
        2014), there are no known, widely-deployed pluggable transports which
        support IPv6. Ergo, this is very likely going to be an IPv4 address.

    :type port: int
    :ivar port: A integer specifying the port which this pluggable transport
        is listening on. (This should likely be whatever port the bridge
        specified in its ``ServerTransportPlugin`` torrc line, unless the
        pluggable transport is running in "managed" mode.)

    :type arguments: dict
    :ivar arguments: Some PTs can take additional arguments, which must be
        distributed to the client out-of-band. These are present in the
        ``@type bridge-extrainfo-document``, in the ``transport`` line like
        so::

            METHOD SP ADDR ":" PORT SP [K=V[,K=V[,K=V[…]]]]

        where K is the key in **arguments**, and V is the value. For example,
        in the case of ``scramblesuit``, for which the client must supply a
        shared secret to the ``scramblesuit`` instance running on the bridge,
        the **arguments** would be something like::

            {'password': 'NEQGQYLUMUQGK5TFOJ4XI2DJNZTS4LRO'}
    """

    def __init__(self, fingerprint=None, methodname=None,
                 address=None, port=None, arguments=None):
        """Create a ``PluggableTransport`` describing a PT running on a bridge.

        :param str fingerprint: The uppercased, hexadecimal fingerprint of the
            identity key of the parent bridge running this pluggable transport.
        :param str methodname: The canonical "name" for this pluggable
            transport. See :data:`methodname`.
        :param str address: The IP address of the transport. See
            :data:`address`.
        :param int port: A integer specifying the port which this pluggable
            transport is listening on.
        :param dict arguments: Any additional arguments which the PT takes,
            which must be distributed to the client out-of-band. See
            :data:`arguments`.
        """
        super(PluggableTransport, self).__init__()
        self._port = None
        self._methodname = None
        self._arguments = None

        self.fingerprint = fingerprint
        self.address = address
        self.port = port
        self.methodname = methodname
        self.arguments = arguments
        self._blockedIn = {}

        # Because we can intitialise this class with the __init__()
        # parameters, or use the ``updateFromStemTransport()`` method, we'll
        # only use the ``_runChecks()`` method now if we were initialised with
        # parameters:
        if (fingerprint or address or port or methodname or arguments):
            self._runChecks()

    def _parseArgumentsIntoDict(self, argumentList):
        """Convert a list of Pluggable Transport arguments into a dictionary
        suitable for :data:`arguments`.

        :param list argumentList: A list of Pluggable Transport
            arguments. There might be multiple, comma-separated ``K=V``
            Pluggable Transport arguments in a single item in the
            **argumentList**, or each item might be its own ``K=V``; we don't
            care and we should be able to parse it either way.
        :rtype: dict
        :returns: A dictionary of all the ``K=V`` Pluggable Transport
            arguments.
        """
        argDict = {}

        # PT argumentss are comma-separated in the extrainfo
        # descriptors. While there *shouldn't* be anything after them that was
        # separated by a space (and hence would wind up being in a different
        # item in `arguments`), if there was we'll join it to the rest of the
        # PT arguments with a comma so that they are parsed as if they were PT
        # arguments as well:
        allArguments = ','.join(argumentList)

        for arg in allArguments.split(','):
            if arg:  # It might be an empty string
                try:
                    key, value = arg.split('=')
                except ValueError:
                    logging.warn("  Couldn't parse K=V from PT arg: %r" % arg)
                else:
                    logging.debug("  Parsed PT Argument: %s: %s" % (key, value))
                    argDict[key] = value

        return argDict

    def _runChecks(self):
        """Validate that we were initialised with acceptable parameters.

        We currently check that:

          1. The :data:`port` is an integer, and that it is between the values
              of ``0`` and ``65535`` (inclusive).

          2. The :data:`arguments` is a dictionary.

        :raises MalformedPluggableTransport: if any of the above checks fails.
        """
        if not self.fingerprint:
            raise MalformedPluggableTransport(
                ("Cannot create %s without owning Bridge fingerprint!")
                % self.__class__.__name__)

        if not self.address:
            raise InvalidPluggableTransportIP(
                ("Cannot create PluggableTransport with address '%s'. "
                 "type(address)=%s.") % (self.address, type(self.address)))

        if not self.port:
            raise MalformedPluggableTransport(
                ("Cannot create PluggableTransport without a valid port."))

        if not isinstance(self.arguments, dict):
            raise MalformedPluggableTransport(
                ("Cannot create PluggableTransport with arguments type: %s")
                % type(self.arguments))

    @property
    def port(self):
        """Get the port number which this ``PluggableTransport`` is listening
        for incoming client connections on.

        :rtype: int or None
        :returns: The port (as an int), if it is known and valid; otherwise,
            returns ``None``.
        """
        return self._port

    @port.setter
    def port(self, value):
        """Store the port number which this ``PluggableTransport`` is listening
        for incoming client connections on.

        :param int value: The transport's port.
        """
        if isinstance(value, int) and (0 <= value <= 65535):
            self._port = value

    @port.deleter
    def port(self):
        """Reset this ``PluggableTransport``'s port to ``None``."""
        self._port = None

    def getTransportLine(self, includeFingerprint=True, bridgePrefix=False):
        """Get a Bridge Line for this :class:`PluggableTransport`.

        .. glossary::

           Bridge Line
             A "Bridge Line" is how BridgeDB refers to lines in a ``torrc``
             file which should begin with the word ``"Bridge"``, and it is how
             a client tells their Tor process that they would like to use a
             particular bridge.

        .. note:: If **bridgePrefix** is ``False``, this method does not
            return lines which are prefixed with the word 'bridge', as they
            would be in a torrc file. Instead, lines returned look like this::

                obfs3 245.102.100.252:23619 59ca743e89b508e16b8c7c6d2290efdfd14eea98

            This was made configurable to fix Vidalia being a brain-damaged
            piece of shit (#5851_). TorLaucher replaced Vidalia soon after,
            and TorLauncher is intelligent enough to understand
            :term:`Bridge Line`s regardless of whether or not they are prefixed
            with the word "Bridge".

        .. _#5851: https://bugs.torproject.org/5851

        :param bool includeFingerprints: If ``True``, include the digest of
            this bridges public identity key in the torrc line.
        :param bool bridgePrefix: If ``True``, add ``'Bridge '`` to the
             beginning of each returned line (suitable for pasting directly
             into a ``torrc`` file).
        :rtype: str
        :returns: A configuration line for adding this Pluggable Transport
            into a ``torrc`` file.
        """
        sections = []

        if bridgePrefix:
            sections.append('Bridge')

        if self.address.version == 6:
            # If the address was IPv6, put brackets around it:
            host = '%s [%s]:%d' % (self.methodname, self.address, self.port)
        else:
            host = '%s %s:%d' % (self.methodname, self.address, self.port)
        sections.append(host)

        if includeFingerprint:
            sections.append(self.fingerprint)

        for key, value in self.arguments.items():
            sections.append('%s=%s' % (key, value))

        line = ' '.join(sections)

        return line

    def updateFromStemTransport(self, fingerprint, methodname, kitchenSink):
        """Update this :class:`PluggableTransport` from the data structure
        which Stem uses.

        Stem's
        :api:`stem.descriptor.extrainfo_descriptor.BridgeExtraInfoDescriptor`
        parses extrainfo ``transport`` lines into a dictionary with the
        following structure::

            {u'obfs2': (u'34.230.223.87', 37339, []),
             u'obfs3': (u'34.230.223.87', 37338, []),
             u'obfs4': (u'34.230.223.87', 37341, [
                 (u'iat-mode=0,'
                  u'node-id=2a79f14120945873482b7823caabe2fcde848722,'
                  u'public-key=0a5b046d07f6f971b7776de682f57c5b9cdc8fa060db7ef59de82e721c8098f4')]),
             u'scramblesuit': (u'34.230.223.87', 37340, [
                 u'password=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'])}

        This method will initialise this class from the dictionary key
        (**methodname**) and its tuple of values (**kitchenSink**).

        :param str fingerprint: The uppercased, hexadecimal fingerprint of the
            identity key of the parent bridge running this pluggable transport.
        :param str methodname: The :data:`methodname` of this Pluggable
            Transport.
        :param tuple kitchenSink: Everything else that was on the
            ``transport`` line in the bridge's extrainfo descriptor, which
            Stem puts into the 3-tuples shown in the example above.
        """
        self.fingerprint = str(fingerprint)
        self.methodname = str(methodname)
        self.address = kitchenSink[0]

        port = kitchenSink[1]
        if port == 'anyport':  # IDK. Stem, WTF?
            port = 0

        self.port = int(port)
        self.arguments = self._parseArgumentsIntoDict(kitchenSink[2])
        self._runChecks()


class BridgeBase(BridgeAddressBase):
    """The base class for all bridge implementations."""

    def __init__(self):
        super(BridgeBase, self).__init__()

        self._nickname = None
        self._orPort = None
        self.socksPort = 0  # Bridges should always have ``SOCKSPort`` and
        self.dirPort = 0    # ``DirPort`` set to ``0``
        self.orAddresses = []
        self.transports = []
        self.flags = Flags()

    @property
    def nickname(self):
        """Get this Bridge's nickname.

        :rtype: str
        :returns: The Bridge's nickname.
        """
        return self._nickname

    @nickname.setter
    def nickname(self, value):
        """Set this Bridge's nickname to **value**.

        .. note:: We don't need to call
            :func:`bridgedb.parse.nickname.isValidRouterNickname() since Stem
            will check nickname specification conformity.

        :param str value: The nickname of this Bridge.
        """
        self._nickname = value

    @nickname.deleter
    def nickname(self):
        """Reset this Bridge's nickname."""
        self._nickname = None

    @property
    def orPort(self):
        """Get this bridge's ORPort.

        :rtype: int
        :returns: This Bridge's default ORPort.
        """
        return self._orPort

    @orPort.setter
    def orPort(self, value):
        """Set this Bridge's ORPort.

        :param int value: The Bridge's ORPort.
        """
        if isinstance(value, int) and (0 <= value <= 65535):
            self._orPort = value

    @orPort.deleter
    def orPort(self):
        """Reset this Bridge's ORPort."""
        self._orPort = None


class BridgeBackwardsCompatibility(BridgeBase):
    """Backwards compatibility methods for the old Bridge class."""

    def __init__(self, nickname=None, ip=None, orport=None,
                 fingerprint=None, id_digest=None, or_addresses=None):
        """Create a Bridge which is backwards compatible with the old Bridge class
        implementation.

        .. info: For backwards compatibility, `nickname`, `ip`, and `orport`
            must be the first, second, and third arguments, respectively.  The
            `fingerprint` and `id_digest` were previously kwargs, and are also
            provided for backwards compatibility.  New calls to
            :meth:`__init__` *should* avoid using these kwargs, and instead
            use the methods :meth:`updateFromNetworkStatus`,
            :meth:`updateFromServerDescriptor`, and
            :meth:`updateFromExtraInfoDescriptor`.
        """
        super(BridgeBackwardsCompatibility, self).__init__()

        self.desc_digest = None
        self.ei_digest = None
        self.running = False
        self.stable = False

        if nickname or ip or orport or fingerprint or id_digest:
            self._backwardsCompatible(nickname=nickname, address=ip,
                                      orPort=orport, fingerprint=fingerprint,
                                      idDigest=id_digest,
                                      orAddresses=or_addresses)

    def _backwardsCompatible(self, nickname=None, address=None, orPort=None,
                             fingerprint=None, idDigest=None,
                             orAddresses=None):
        """Functionality for maintaining backwards compatibility with the older
        version of this class (see :class:`bridgedb.test.deprecated.Bridge`).
        """
        self.nickname = nickname
        self.orPort = orPort
        if address:
            self.address = address

        if idDigest:
            if not fingerprint:
                if not len(idDigest) == 20:
                    raise TypeError("Bridge with invalid ID")
                self.fingerprint = toHex(idDigest)
        elif fingerprint:
            if not isValidFingerprint(fingerprint):
                raise TypeError("Bridge with invalid fingerprint (%r)"
                                % fingerprint)
            self.fingerprint = fingerprint.lower()
        else:
            raise TypeError("Bridge with no ID")

        if orAddresses and isinstance(orAddresses, dict):
            for ip, portlist in orAddresses.items():
                validAddress = isIPAddress(ip, compressed=False)
                if validAddress:
                    # The old code expected a `bridgedb.parse.addr.PortList`:
                    if isinstance(portlist, PortList):
                        for port in portlist.ports:
                            self.orAddresses.append(
                                (validAddress, port, validAddress.version,))
                    elif isinstance(portlist, int):
                        self.orAddresses.append(
                            (validAddress, portlist, validAddress.version,))
                    else:
                        logging.warn("Can't parse port for ORAddress %r: %r"
                                     % (ip, portlist))

    def getID(self):
        """Get the binary encoded form of this ``Bridge``'s ``fingerprint``.

        This method is provided for backwards compatibility and should not
        be relied upon.
        """
        if self.fingerprint:
            return fromHex(self.fingerprint)

    def setDescriptorDigest(self, digest):
        """Set this ``Bridge``'s server-descriptor digest.

        This method is provided for backwards compatibility and should not
        be relied upon.
        """
        self.desc_digest = digest  # old attribute for backwards compat
        self.descriptorDigest = digest  # new attribute

    def setExtraInfoDigest(self, digest):
        """Set this ``Bridge``'s extrainfo digest.

        This method is provided for backwards compatibility and should not
        be relied upon.
        """
        self.ei_digest = digest  # old attribute for backwards compat
        self.extrainfoDigest = digest  # new attribute

    def setStatus(self, running=None, stable=None):
        """Set this ``Bridge``'s "Running" and "Stable" flags.

        This method is provided for backwards compatibility and should not
        be relied upon.
        """
        if running is not None:
            self.running = bool(running)
            self.flags.running = bool(running)
        if stable is not None:
            self.stable = bool(stable)
            self.flags.stable = bool(running)

    def getConfigLine(self, includeFingerprint=False, addressClass=None,
                      request=None, transport=None):
        """Get a vanilla bridge line for this ``Bridge``.

        This method is provided for backwards compatibility and should not
        be relied upon.

        The old ``bridgedb.Bridges.Bridge.getConfigLine()`` method didn't know
        about :class:`~bridgedb.bridgerequest.BridgeRequestBase`s, and so this
        modified version is backwards compatible by creating a
        :class:`~bridgedb.bridgerequest.BridgeRequestBase` for
        :meth:`getBridgeLine`. The default parameters are the same as they
        were in the old ``bridgedb.Bridges.Bridge`` class.

        :param bool includeFingerprint: If ``True``, include the
            ``fingerprint`` of this :class:`Bridge` in the returned bridge
            line.
        :type addressClass: :class:`ipaddr.IPv4Address` or
            :class:`ipaddr.IPv6Address`.
        :param addressClass: Type of address to choose.
        :param str request: A string unique to this request e.g. email-address
            or ``uniformMap(ip)`` or ``'default'``. In this case, this is not
            a :class:`~bridgerequest.BridgeRequestBase` (as might be expected)
            but the equivalent of
            :data:`bridgerequest.BridgeRequestBase.client`.
        :param str transport: A pluggable transport method name.
        """
        bridgeRequest = bridgerequest.BridgeRequestBase(addressClass)
        bridgeRequest.client = request if request else bridgeRequest.client
        bridgeRequest.isValid(True)

        if transport:
            bridgeRequest.withPluggableTransportType(transport)

        bridgeRequest.generateFilters()
        bridgeLine = self.getBridgeLine(bridgeRequest, includeFingerprint)
        return bridgeLine

    # Bridge Stability (`#5482 <https://bugs.torproject.org>`_) properties.
    @property
    def familiar(self):
        """A bridge is "familiar" if 1/8 of all active bridges have appeared
        more recently than it, or if it has been around for a Weighted Time of
        eight days.
        """
        with bridgedb.Storage.getDB() as db:  # pragma: no cover
            return db.getBridgeHistory(self.fingerprint).familiar

    @property
    def wfu(self):
        """Weighted Fractional Uptime"""
        with bridgedb.Storage.getDB() as db:  # pragma: no cover
            return db.getBridgeHistory(self.fingerprint).weightedFractionalUptime

    @property
    def weightedTime(self):
        """Weighted Time"""
        with bridgedb.Storage.getDB() as db:  # pragma: no cover
            return db.getBridgeHistory(self.fingerprint).weightedTime

    @property
    def wmtbac(self):
        """Weighted Mean Time Between Address Change"""
        with bridgedb.Storage.getDB() as db:  # pragma: no cover
            return db.getBridgeHistory(self.fingerprint).wmtbac

    @property
    def tosa(self):
        """The Time On Same Address (TOSA)"""
        with bridgedb.Storage.getDB() as db:  # pragma: no cover
            return db.getBridgeHistory(self.fingerprint).tosa

    @property
    def weightedUptime(self):
        """Weighted Uptime"""
        with bridgedb.Storage.getDB() as db:  # pragma: no cover
            return db.getBridgeHistory(self.fingerprint).weightedUptime


class Bridge(BridgeBackwardsCompatibility):
    """A single bridge, and all the information we have for it.

    :type fingerprint: str or ``None``
    :ivar fingerprint: This ``Bridge``'s fingerprint, in lowercased
        hexadecimal format.

    :type nickname: str or ``None``
    :ivar nickname: This ``Bridge``'s router nickname.

    :type socksPort: int
    :ivar socksPort: This ``Bridge``'s SOCKSPort. Should always be ``0``.

    :type dirPort: int
    :ivar dirPort: This ``Bridge``'s DirPort. Should always be ``0``.

    :type orAddresses: list
    :ivar orAddresses: A list of 3-tuples in the form::
            (ADDRESS, PORT, IP_VERSION)
        where:
            * ADDRESS is an :class:`ipaddr.IPAddress`,
            * PORT is an ``int``,
            * IP_VERSION is either ``4`` or ``6``.

    :type transports: list
    :ivar transports: A list of :class:`PluggableTransport`s, one for each
        transport that this :class:`Bridge` currently supports.

    :type flags: :class:`~bridgedb.bridges.Flags`
    :ivar flags: All flags assigned by the BridgeAuthority to this
        :class:`Bridge`.

    :type hibernating: bool
    :ivar hibernating: ``True`` if this :class:`Bridge` is hibernating and not
        currently serving clients (e.g. if the Bridge hit its configured
        ``RelayBandwidthLimit``); ``False`` otherwise.

    :type _blockedIn: dict
    :ivar _blockedIn: A dictionary of ``ADDRESS:PORT`` pairs to lists of
        lowercased, two-letter country codes (e.g. ``"us"``, ``"gb"``,
        ``"cn"``, etc.) which that ``ADDRESS:PORT`` pair is blocked in.

    :type contact: str or ``None``
    :ivar contact: The contact information for the this Bridge's operator.

    :type family: set or ``None``
    :ivar family: The fingerprints of other Bridges related to this one.

    :type platform: str or ``None``
    :ivar platform: The ``platform`` line taken from the
        ``@type bridge-server-descriptor``, e.g.
        ``'Tor 0.2.5.4-alpha on Linux'``.

    :type software: :api:`stem.version.Version` or ``None``
    :ivar software: The OR version portion of the ``platform`` line.

    :type os: str or None
    :ivar os: The OS portion of the ``platform`` line.
    """
    #: (bool) If ``True``, check that the signature of the bridge's
    #: ``@type bridge-server-descriptor`` is valid and that the signature was
    #: created with the ``signing-key`` contained in that descriptor.
    _checkServerDescriptorSignature = True

    def __init__(self, *args, **kwargs):
        """Create a and store information for a new ``Bridge``.

        .. info: For backwards compatibility, `nickname`, `ip`, and `orport`
            must be the first, second, and third arguments, respectively.  The
            `fingerprint` and `id_digest` were previously kwargs, and are also
            provided for backwards compatibility.  New calls to
            :meth:`__init__` *should* avoid using these kwargs, and instead
            use the methods :meth:`updateFromNetworkStatus`,
            :meth:`updateFromServerDescriptor`, and
            :meth:`updateFromExtraInfoDescriptor`.
        """
        super(Bridge, self).__init__(*args, **kwargs)

        self.socksPort = 0  # Bridges should always have ``SOCKSPort`` and
        self.dirPort = 0    # ``DirPort`` set to ``0``
        self.orAddresses = []
        self.transports = []
        self.flags = Flags()
        self.hibernating = False
        self._blockedIn = {}

        self.bandwidth = None
        self.bandwidthAverage = None
        self.bandwidthBurst = None
        self.bandwidthObserved = None

        self.contact = None
        self.family = None
        self.platform = None
        self.software = None
        self.os = None
        self.uptime = None
        self.bridgeIPs = None

        self.onionKey = None
        self.ntorOnionKey = None
        self.signingKey = None

        self.descriptors = {'networkstatus': None,
                            'server': None,
                            'extrainfo': None}

        #: The hash digest of this bridge's ``@type bridge-server-descriptor``,
        #: as signed (but not including the signature). This is found in the
        #: 'r'-line of this bridge's ``@type bride-networkstatus`` document,
        #: however it is stored here re-encoded from base64 into hexadecimal,
        #: and converted to uppercase.
        self.descriptorDigest = None
        self.extrainfoDigest = None

    def __str__(self):
        """Return a pretty string representation that identifies this Bridge.

        .. warning:: With safelogging disabled, the returned string contains
            the bridge's fingerprint, which should be handled with care.

        If safelogging is enabled, the returned string will have the SHA-1
        hash of the bridge's fingerprint (a.k.a. a hashed fingerprint).

        Hashed fingerprints will be prefixed with ``'$$'``, and the real
        fingerprints are prefixed with ``'$'``.

        :rtype: str
        :returns: A string in the form:
            :data:`nickname```.$``:data:`fingerprint`.
        """
        nickname = self.nickname if self.nickname else 'Unnamed'
        prefix = '$'
        separator = "~"
        fingerprint = self.fingerprint

        if safelog.safe_logging:
            prefix = '$$'
            if fingerprint:
                fingerprint = hashlib.sha1(fingerprint).hexdigest().upper()

        if not fingerprint:
            fingerprint = '0' * 40

        return prefix + fingerprint + separator + nickname

    def _checkServerDescriptor(self, descriptor):
        # If we're parsing the server-descriptor, require a networkstatus
        # document:
        if not self.descriptors['networkstatus']:
            raise ServerDescriptorWithoutNetworkstatus(
                ("We received a server-descriptor for bridge '%s' which has "
                 "no corresponding networkstatus document.") %
                descriptor.fingerprint)

        ns = self.descriptors['networkstatus']

        # We must have the digest of the server-descriptor from the
        # networkstatus document:
        if not self.descriptorDigest:
            raise MissingServerDescriptorDigest(
                ("The server-descriptor digest was missing from networkstatus "
                 "document for bridge '%s'.") % descriptor.fingerprint)

        digested = descriptor.digest()
        # The digested server-descriptor must match the digest reported by the
        # BridgeAuthority in the bridge's networkstatus document:
        if not self.descriptorDigest == digested:
            raise ServerDescriptorDigestMismatch(
                ("The server-descriptor digest for bridge '%s' doesn't match "
                 "the digest reported by the BridgeAuthority in the "
                 "networkstatus document: \n"
                 "Digest reported in networkstatus: %s\n"
                 "Actual descriptor digest:         %s\n") %
                (descriptor.fingerprint, self.descriptorDigest, digested))

    def _constructBridgeLine(self, addrport, includeFingerprint=True,
                             bridgePrefix=False):
        """Construct a :term:`Bridge Line` from an (address, port) tuple.

        :param tuple addrport: A 3-tuple of ``(address, port, ipversion)``
            where ``address`` is a string, ``port`` is an integer, and
            ``ipversion`` is a integer (``4`` or ``6``).
        :param bool includeFingerprint: If ``True``, include the
            ``fingerprint`` of this :class:`Bridge` in the returned bridge
            line.
        :param bool bridgePrefix: if ``True``, prefix the :term:`Bridge Line`
            with ``'Bridge '``.
        :rtype: string
        :returns: A bridge line suitable for adding into a ``torrc`` file or
            Tor Launcher.
        """
        if not addrport:
            return

        address, port, version = addrport
        bridgeLine = []

        if bridgePrefix:
            bridgeLine.append('Bridge')

        if version == 4:
            bridgeLine.append("%s:%d" % (str(address), port))
        elif version == 6:
            bridgeLine.append("[%s]:%d" % (str(address), port))

        if includeFingerprint:
            bridgeLine.append("%s" % self.fingerprint)

        return ' '.join(bridgeLine)

    @classmethod
    def _getBlockKey(cls, address, port):
        """Format an **address**:**port** pair appropriately for use as a key
        in the :data:`_blockedIn` dictionary.

        :param address: An IP address of this :class:`Bridge` or one of its
            :data:`transports`.
        :param port: A port.
        :rtype: str
        :returns: A string in the form ``"ADDRESS:PORT"`` for IPv4 addresses,
            and ``"[ADDRESS]:PORT`` for IPv6.
        """
        if isIPv6(str(address)):
            key = "[%s]:%s" % (address, port)
        else:
            key = "%s:%s" % (address, port)

        return key

    def _getTransportForRequest(self, bridgeRequest):
        """If a transport was requested, return the correlated
        :term:`Bridge Line` based upon the client identifier in the
        **bridgeRequest**.

        :type bridgeRequest: :class:`bridgedb.bridgerequest.BridgeRequestBase`
        :param bridgeRequest: A ``BridgeRequest`` which stores all of the
            client-specified options for which type of bridge they want to
            receive.
        :raises PluggableTransportUnavailable: if this bridge doesn't have any
            of the requested pluggable transport type. This shouldn't happen
            because the bridges are filtered into the client's hashring based
            on the **bridgeRequest** options, however, this is useful in the
            unlikely event that it does happen, so that the calling function
            can fetch an additional bridge from the hashring as recompense for
            what would've otherwise been a missing :term:`Bridge Line`.
        :rtype: str or ``None``
        :returns: If no transports were requested, return ``None``, otherwise
            return a :term:`Bridge Line` for the requested pluggable transport
            type.
        """
        addressClass = bridgeRequest.addressClass
        desiredTransport = bridgeRequest.justOnePTType()
        hashringPosition = bridgeRequest.getHashringPlacement(bridgeRequest.client,
                                                              'Order-Or-Addresses')

        logging.info("Bridge %s answering request for %s transport..." %
                     (safelog.logSafely(self.fingerprint), desiredTransport))
        # Filter all this Bridge's ``transports`` according to whether or not
        # their ``methodname`` matches the requested transport, i.e. only
        # 'obfs3' transports, or only 'scramblesuit' transports:
        transports = filter(lambda pt: desiredTransport == pt.methodname,
                            self.transports)
        # Filter again for whichever of IPv4 or IPv6 was requested:
        transports = filter(lambda pt: isinstance(pt.address, addressClass),
                            transports)

        if transports:
            return transports[hashringPosition % len(transports)]
        else:
            raise PluggableTransportUnavailable(
                ("Client requested transport %s from bridge %s, but this "
                 "bridge doesn't have any of that transport!") %
                (desiredTransport, self.fingerprint))

    def _getVanillaForRequest(self, bridgeRequest):
        """If vanilla bridges were requested, return the assigned
        :term:`Bridge Line` based upon the client identifier in the
        **bridgeRequest**.

        :type bridgeRequest: :class:`bridgedb.bridgerequest.BridgeRequestBase`
        :param bridgeRequest: A ``BridgeRequest`` which stores all of the
            client-specified options for which type of bridge they want to
            receive.
        :rtype: str or ``None``
        :returns: If no transports were requested, return ``None``, otherwise
            return a :term:`Bridge Line` for the requested pluggable transport
            type.
        """
        logging.info(
            "Bridge %s answering request for IPv%s vanilla address..." %
            (self, "6" if bridgeRequest.addressClass is ipaddr.IPv6Address else "4"))

        if not bridgeRequest.filters:
            logging.debug(("Request %s didn't have any filters; "
                           "generating them now...") % bridgeRequest)
            bridgeRequest.generateFilters()

        addresses = self.allVanillaAddresses

        # Filter ``allVanillaAddresses`` by whether IPv4 or IPv6 was requested:
        addresses = filter(
            # ``address`` here is a 3-tuple:
            # ``(ipaddr.IPAddress, int(port), int(ipaddr.IPAddress.version))``
            lambda address: isinstance(address[0], bridgeRequest.addressClass),
            self.allVanillaAddresses)

        if addresses:
            # Use the client's unique data to HMAC them into their position in
            # the hashring of filtered bridges addresses:
            position = bridgeRequest.getHashringPlacement('Order-Or-Addresses',
                                                          bridgeRequest.client)
            logging.debug("Client's hashring position is %r" % position)
            vanilla = addresses[position % len(addresses)]
            logging.info("Got vanilla bridge for client.")

            return vanilla

    def _updateORAddresses(self, orAddresses):
        """Update this :class:`Bridge`'s :data:`orAddresses` attribute from a
        3-tuple (i.e. as Stem creates when parsing descriptors).

        :param tuple orAddresses: A 3-tuple of: an IP address, a port number,
            and a boolean (``False`` if IPv4, ``True`` if IPv6).
        :raises FutureWarning: if any IPv4 addresses are found. As of
            tor-0.2.5, only IPv6 addresses should be found in a descriptor's
            `ORAddress` line.
        """
        for (address, port, ipVersion) in orAddresses:
            version = 6
            if not ipVersion:  # `False` means IPv4; `True` means IPv6.
                # See https://bugs.torproject.org/9380#comment:27
                warnings.warn(FutureWarning((
                    "Got IPv4 address in 'a'/'or-address' line! Descriptor "
                     "format may have changed!")))
                version = 4

            validatedAddress = isIPAddress(address, compressed=False)
            if validatedAddress:
                self.orAddresses.append( (validatedAddress, port, version,) )

    @property
    def allVanillaAddresses(self):
        """Get all valid, non-PT address:port pairs for this bridge.

        :rtype: list
        :returns: All of this bridge's ORAddresses, as well as its ORPort IP
            address and port.
        """
        addresses = self.orAddresses
        # Add the default ORPort address (it will always be IPv4, otherwise
        # Stem should have raised a ValueError during parsing):
        addresses.append((self.address, self.orPort, 4))
        return addresses

    def assertOK(self):
        """Perform some additional validation on this bridge's info.

        We require that:

          1. Any IP addresses contained in :data:`orAddresses` are valid,
             according to :func:`~bridgedb.parse.addr.isValidIP`.

          2. Any ports in :data:`orAddresses` are between ``1`` and ``65535``
             (inclusive).

          3. All IP version numbers given in :data:`orAddresses` are either
             ``4`` or ``6``.

        .. todo:: This should probably be reimplemented as a property that
            automatically sanitises the values for each ORAddress, as is done
            for :property:`bridgedb.bridges.BridgeAddressBase.address` and
            :property:`bridgedb.bridges.BridgeBase.orPort`.

        :raises MalformedBridgeInfo: if something was found to be malformed or
            invalid.
        """
        malformed = []

        for (address, port, version) in self.orAddresses:
            if not isValidIP(address):
                malformed.append("Invalid ORAddress address: '%s'" % address)
            if not (0 <= port <= 65535):
                malformed.append("Invalid ORAddress port: '%d'" % port)
            if not version in (4, 6):
                malformed.append("Invalid ORAddress IP version: %r" % version)

        if malformed:
            raise MalformedBridgeInfo('\n'.join(malformed))

    def getBridgeLine(self, bridgeRequest, includeFingerprint=True,
                      bridgePrefix=False):
        """Return a valid :term:`Bridge Line` for a client to give to Tor
        Launcher or paste directly into their ``torrc``.

        This is a helper method to call either :meth:`_getTransportForRequest`
        or :meth:`_getVanillaForRequest` depending on whether or not any
        :class:`PluggableTransport`s were requested in the
        :class:`bridgeRequest <bridgedb bridgerequest.BridgeRequestBase>`, and
        then construct the :term:`Bridge Line` accordingly.

        :type bridgeRequest: :class:`bridgedb.bridgerequest.BridgeRequestBase`
        :param bridgeRequest: A ``BridgeRequest`` which stores all of the
            client-specified options for which type of bridge they want to
            receive.
        :param bool includeFingerprint: If ``True``, include the
            ``fingerprint`` of this :class:`Bridge` in the returned bridge
            line.
        :param bool bridgePrefix: if ``True``, prefix the :term:`Bridge Line`
            with ``'Bridge '``.
        """
        if not bridgeRequest.isValid():
            logging.info("Bridge request was not valid. Dropping request.")
            return  # XXX raise error perhaps?

        if bridgeRequest.transports:
            pt = self._getTransportForRequest(bridgeRequest)
            bridgeLine = pt.getTransportLine(includeFingerprint, bridgePrefix)
        else:
            addrport = self._getVanillaForRequest(bridgeRequest)
            bridgeLine = self._constructBridgeLine(addrport,
                                                   includeFingerprint,
                                                   bridgePrefix)
        return bridgeLine

    def _addBlockByKey(self, key, countryCode):
        """Create or append to the list of blocked countries for a **key**.

        :param str key: The key to lookup in the :data:`Bridge._blockedIn`
            dictionary. This should be in the form returned by
            :classmethod:`_getBlockKey`.
        :param str countryCode: A two-character country code specifier.
        """
        if self._blockedIn.has_key(key):
            self._blockedIn[key].append(countryCode.lower())
        else:
            self._blockedIn[key] = [countryCode.lower(),]

    def addressIsBlockedIn(self, countryCode, address, port):
        """Determine if a specific (address, port) tuple is blocked in
        **countryCode**.

        :param str countryCode: A two-character country code specifier.
        :param str address: An IP address (presumedly one used by this
            bridge).
        :param int port: A port.
        :rtype: bool
        :returns: ``True`` if the **address**:**port** pair is blocked in
            **countryCode**, ``False`` otherwise.
        """
        key = self._getBlockKey(address, port)

        try:
            if countryCode.lower() in self._blockedIn[key]:
                logging.info("Vanilla address %s of bridge %s blocked in %s."
                             % (key, self, countryCode.lower()))
                return True
        except KeyError:
            return False  # That address:port pair isn't blocked anywhere

        return False

    def transportIsBlockedIn(self, countryCode, methodname):
        """Determine if any of a specific type of pluggable transport which
        this bridge might be running is blocked in a specific country.

        :param str countryCode: A two-character country code specifier.
        :param str methodname: The type of pluggable transport to check,
            i.e. ``'obfs3'``.
        :rtype: bool
        :returns: ``True`` if any address:port pair which this bridge is
            running a :class:`PluggableTransport` on is blocked in
            **countryCode**, ``False`` otherwise.
        """
        for pt in self.transports:
            if pt.methodname.lower() == methodname.lower():
                if self.addressIsBlockedIn(countryCode, pt.address, pt.port):
                    logging.info("Transport %s of bridge %s is blocked in %s."
                                 % (pt.methodname, self, countryCode))
                    return True
        return False

    def isBlockedIn(self, countryCode):
        """Determine, according to our stored bridge reachability reports, if
        any of the address:port pairs used by this :class:`Bridge` or it's
        :data:`transports` are blocked in **countryCode**.

        :param str countryCode: A two-character country code specifier.
        :rtype: bool
        :returns: ``True`` if at least one address:port pair used by this
            bridge is blocked in **countryCode**; ``False`` otherwise.
        """
        # Check all supported pluggable tranport types:
        for methodname in self.supportedTransportTypes:
            if self.transportIsBlockedIn(countryCode.lower(), methodname):
                return True

        for address, port, version in self.allVanillaAddresses:
            if self.addressIsBlockedIn(countryCode.lower(), address, port):
                return True

        return False

    def setBlockedIn(self, countryCode, address=None, port=None, methodname=None):
        """Mark this :class:`Bridge` as being blocked in **countryCode**.

        By default, if called with no parameters other than a **countryCode**,
        we'll mark all this :class:`Bridge`'s :data:`allVanillaAddresses` and
        :data:`transports` as being blocked.

        Otherwise, we'll filter on any and all parameters given.

        If only a **methodname** is given, then we assume that all
        :data:`transports` with that **methodname** are blocked in
        **countryCode**. If the methodname is ``"vanilla"``, then we assume
        each address in data:`allVanillaAddresses` is blocked.

        :param str countryCode: A two-character country code specifier.
        :param address: An IP address of this Bridge or one of its
            :data:`transports`.
        :param port: A specific port that is blocked, if available. If the
            **port** is ``None``, then any address this :class:`Bridge` or its
            :class:`PluggableTransport`s has that matches the given **address**
            will be marked as block, regardless of its port. This parameter
            is ignored unless an **address** is given.
        :param str methodname: A :data:`PluggableTransport.methodname` to
            match. Any remaining :class:`PluggableTransport`s from
            :data:`transports` which matched the other parameters and now also
            match this **methodname** will be marked as being blocked in
            **countryCode**.
        """
        vanillas   = self.allVanillaAddresses
        transports = self.transports

        if methodname:
            # Don't process the vanilla if we weren't told to do so:
            if not (methodname == 'vanilla') and not (address or port):
                vanillas = []

            transports = filter(lambda pt: methodname == pt.methodname, transports)

        if address:
            vanillas   = filter(lambda ip: str(address) == str(ip[0]), vanillas)
            transports = filter(lambda pt: str(address) == str(pt.address), transports)

        if port:
            vanillas   = filter(lambda ip: int(port) == int(ip[1]), vanillas)
            transports = filter(lambda pt: int(port) == int(pt.port), transports)

        for addr, port, _ in vanillas:
            key = self._getBlockKey(addr, port)
            logging.info("Vanilla address %s for bridge %s is now blocked in %s."
                         % (key, self, countryCode))
            self._addBlockByKey(key, countryCode)

        for transport in transports:
            key = self._getBlockKey(transport.address, transport.port)
            logging.info("Transport %s %s for bridge %s is now blocked in %s."
                         % (transport.methodname, key, self, countryCode))
            self._addBlockByKey(key, countryCode)
            transport._blockedIn[key] = self._blockedIn[key]

    def getDescriptorLastPublished(self):
        """Get the timestamp for when this bridge's last known server
        descriptor was published.

        :rtype: :type:`datetime.datetime` or ``None``
        :returns: A datetime object representing the timestamp of when the
            last known ``@type bridge-server-descriptor`` was published, or
            ``None`` if we have never seen a server descriptor for this
            bridge.
        """
        return getattr(self.descriptors['server'], 'published', None)

    def getExtrainfoLastPublished(self):
        """Get the timestamp for when this bridge's last known extrainfo
        descriptor was published.

        :rtype: :type:`datetime.datetime` or ``None``
        :returns: A datetime object representing the timestamp of when the
            last known ``@type bridge-extrainfo`` descriptor was published, or
            ``None`` if we have never seen an extrainfo descriptor for this
            bridge.
        """
        return getattr(self.descriptors['extrainfo'], 'published', None)

    def getNetworkstatusLastPublished(self):
        """Get the timestamp for when this bridge's last known networkstatus
        descriptor was published.

        :rtype: :type:`datetime.datetime` or ``None``
        :returns: A datetime object representing the timestamp of when the
            last known ``@type networkstatus-bridge`` document was published,
            or ``None`` if we have never seen a networkstatus document for
            this bridge.
        """
        return getattr(self.descriptors['networkstatus'], 'published', None)

    @property
    def supportedTransportTypes(self):
        """A deduplicated list of all the :data:`PluggableTranport.methodname`s
        which this bridge supports.
        """
        return list(set([pt.methodname for pt in self.transports]))

    def updateFromNetworkStatus(self, descriptor):
        """Update this bridge's attributes from a parsed networkstatus
        descriptor.

        :type ns: :api:`stem.descriptors.router_status_entry.RouterStatusEntry`
        :param ns:
        """
        self.descriptors['networkstatus'] = descriptor

        # These fields are *only* found in the networkstatus document:
        self.descriptorDigest = descriptor.digest
        self.flags.update(descriptor.flags)
        self.bandwidth = descriptor.bandwidth

        # These fields are also found in the server-descriptor. We will prefer
        # to use the information taken later from the server-descriptor
        # because it is signed by the bridge. However, for now, we harvest all
        # the info we can:
        self.fingerprint = descriptor.fingerprint
        self.nickname = descriptor.nickname
        self.address = descriptor.address
        self.orPort = descriptor.or_port

        self._updateORAddresses(descriptor.or_addresses)

    def updateFromServerDescriptor(self, descriptor):
        """Update this bridge's info from an ``@type bridge-server-descriptor``.

        .. info::
            If :func:`~bridgedb.parse.descriptor.parseServerDescriptorFile` is
            called with ``validate=True``, then Stem will handle checking that
            the ``signing-key`` hashes to the ``fingerprint``. Stem will also
            check that the ``router-signature`` on the descriptor is valid,
            was created with the ``signing-key``, and is a signature of the
            correct digest of the descriptor document (it recalculates the
            digest for the descriptor to ensure that the signed one and the
            actual digest match).

        :type descriptor:
            :api:`stem.descriptor.server_descriptor.RelayDescriptor`
        :param descriptor: The bridge's server descriptor to gather data from.
        :raises MalformedBridgeInfo: If this Bridge has no corresponding
            networkstatus entry, or its **descriptor** digest didn't match the
            expected digest (from the networkstatus entry).
        """
        self._checkServerDescriptor(descriptor)
        self.descriptors['server'] = descriptor

        # Replace the values which we harvested from the networkstatus
        # descriptor, because that one isn't signed with the bridge's identity
        # key.
        self.fingerprint = descriptor.fingerprint
        self.address = descriptor.address
        self.nickname = descriptor.nickname
        self.orPort = descriptor.or_port
        self._updateORAddresses(descriptor.or_addresses)
        self.hibernating = descriptor.hibernating

        self.onionKey = descriptor.onion_key
        self.ntorOnionKey = descriptor.ntor_onion_key
        self.signingKey = descriptor.signing_key

        self.bandwidthAverage = descriptor.average_bandwidth
        self.bandwidthBurst = descriptor.burst_bandwidth
        self.bandwidthObserved = descriptor.observed_bandwidth

        self.contact = descriptor.contact
        self.family = descriptor.family
        self.platform = descriptor.platform
        self.software = descriptor.tor_version
        self.os = descriptor.operating_system
        self.uptime = descriptor.uptime

        self.extrainfoDigest = descriptor.extra_info_digest

    def _verifyExtraInfoSignature(self, descriptor):
        """Verify the signature on the contents of this :class:`Bridge`'s
        ``@type bridge-extrainfo`` descriptor.

        :type descriptor:
            :api:`stem.descriptor.extrainfo_descriptor.RelayExtraInfoDescriptor`
        :param descriptor: An ``@type bridge-extrainfo`` descriptor for this
            :class:`Bridge`, parsed with Stem.
        :raises InvalidExtraInfoSignature: if the signature was invalid,
            missing, malformed, or couldn't be verified successfully.
        :returns: ``None`` if the signature was valid and verifiable.
        """
        # The blocksize is always 128 bits for a 1024-bit key
        BLOCKSIZE = 128

        TOR_SIGNING_KEY_HEADER = u'-----BEGIN RSA PUBLIC KEY-----\n'
        TOR_SIGNING_KEY_FOOTER = u'-----END RSA PUBLIC KEY-----'
        TOR_BEGIN_SIGNATURE = u'-----BEGIN SIGNATURE-----\n'
        TOR_END_SIGNATURE = u'-----END SIGNATURE-----\n'

        logging.info("Verifying extrainfo signature for %s..." % self)

        # Get the bytes of the descriptor signature without the headers:
        document, signature = descriptor.get_bytes().split(TOR_BEGIN_SIGNATURE)
        signature = signature.replace(TOR_END_SIGNATURE, '')
        signature = signature.replace('\n', '')
        signature = signature.strip()

        try:
            # Get the ASN.1 sequence:
            sequence = asn1.DerSequence()

            key = self.signingKey
            key = key.strip(TOR_SIGNING_KEY_HEADER)
            key = key.strip(TOR_SIGNING_KEY_FOOTER)
            key = key.replace('\n', '')
            key = base64.b64decode(key)

            sequence.decode(key)

            modulus = sequence[0]
            publicExponent = sequence[1]

            # The public exponent of RSA signing-keys should always be 65537,
            # but we're not going to turn them down if they want to use a
            # potentially dangerous exponent.
            if publicExponent != 65537:  # pragma: no cover
                logging.warn("Odd RSA exponent in signing-key for %s: %s" %
                             (self, publicExponent))

            # Base64 decode the signature:
            signatureDecoded = base64.b64decode(signature)

            # Convert the signature to a long:
            signatureLong = bytes_to_long(signatureDecoded)

            # Decrypt the long signature with the modulus and public exponent:
            decryptedInt = pow(signatureLong, publicExponent, modulus)

            # Then convert it back to a byte array:
            decryptedBytes = long_to_bytes(decryptedInt, BLOCKSIZE)

            # Remove the PKCS#1 padding from the signature:
            unpadded = removePKCS1Padding(decryptedBytes)

            # This is the hexadecimal SHA-1 hash digest of the descriptor document
            # as it was signed:
            signedDigest = codecs.encode(unpadded, 'hex_codec')
            actualDigest = hashlib.sha1(document).hexdigest()

        except Exception as error:
            logging.debug("Error verifying extrainfo signature: %s" % error)
            raise InvalidExtraInfoSignature(
                "Extrainfo signature for %s couldn't be decoded: %s" %
                (self, signature))
        else:
            if signedDigest != actualDigest:
                raise InvalidExtraInfoSignature(
                    ("The extrainfo digest signed by bridge %s didn't match the "
                     "actual digest.\nSigned digest: %s\nActual digest: %s") %
                    (self, signedDigest, actualDigest))
            else:
                logging.info("Extrainfo signature was verified successfully!")

    def updateFromExtraInfoDescriptor(self, descriptor, verify=True):
        """Update this bridge's information from an extrainfo descriptor.

        Stem's
        :api:`stem.descriptor.extrainfo_descriptor.BridgeExtraInfoDescriptor`
        parses extrainfo ``transport`` lines into a dictionary with the
        following structure::

            {u'obfs2': (u'34.230.223.87', 37339, []),
             u'obfs3': (u'34.230.223.87', 37338, []),
             u'obfs4': (u'34.230.223.87', 37341, [
                 (u'iat-mode=0,'
                  u'node-id=2a79f14120945873482b7823caabe2fcde848722,'
                  u'public-key=0a5b046d07f6f971b7776de682f57c5b9cdc8fa060db7ef59de82e721c8098f4')]),
             u'scramblesuit': (u'34.230.223.87', 37340, [
                 u'password=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'])}


        .. todo:: The ``transport`` attribute of Stem's
            ``BridgeExtraInfoDescriptor`` class is a dictionary that uses the
            Pluggable Transport's eype as the keys. Meaning that if a bridge
            were to offer four instances of ``obfs3``, only one of them would
            get to us through Stem. This might pose a problem someday.

        :type descriptor:
            :api:`stem.descriptor.extrainfo_descriptor.BridgeExtraInfoDescriptor`
        :param descriptor: DOCDOC
        :param bool verify: If ``True``, check that the ``router-signature``
            on the extrainfo **descriptor** is a valid signature from
            :data:`signingkey`.
        """
        if verify:
            try:
                self._verifyExtraInfoSignature(descriptor)
            except InvalidExtraInfoSignature as error:
                logging.warn(error)
                logging.info(("Tossing extrainfo descriptor due to an invalid "
                              "signature."))
                return

        self.descriptors['extrainfo'] = descriptor
        self.bridgeIPs = descriptor.bridge_ips

        oldTransports = self.transports[:]

        for methodname, (address, port, args) in descriptor.transport.items():
            updated = False
            # See if we already know about this transport. If so, update its
            # info; otherwise, add a new transport below.
            for pt in self.transports:
                if pt.methodname == methodname:

                    logging.info("Found old %s transport for %s... Updating..."
                                 % (methodname, self))

                    if not (address == str(pt.address)) and (port == pt.port):
                        logging.info(("Address/port for %s transport for "
                                      "%s changed: old=%s:%s new=%s:%s")
                                     % (methodname, self, pt.address, pt.port,
                                        address, port))

                    oldTransports.remove(pt)
                    pt.updateFromStemTransport(str(self.fingerprint),
                                               methodname,
                                               (address, port, args,))
                    updated = True
                    break

            if updated:
                continue
            else:
                # We didn't update it. It must be a new transport for this
                # bridges that we're hearing about for the first time, so add
                # it:
                logging.info(
                    "Received new %s pluggable transport for bridge %s."
                    % (methodname, self))
                transport = PluggableTransport()
                transport.updateFromStemTransport(str(self.fingerprint),
                                                  methodname,
                                                  (address, port, args,))
                self.transports.append(transport)

        # These are the pluggable transports which we knew about before, which
        # however were not updated in this descriptor, ergo the bridge must
        # not have them any more:
        for pt in oldTransports:
            logging.info("Removing dead transport for bridge %s: %s %s:%s %s" %
                         (self, pt.methodname, pt.address, pt.port, pt.arguments))
            self.transports.remove(pt)
