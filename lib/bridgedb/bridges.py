# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_bridges -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: please see the AUTHORS file for attributions
# :copyright: (c) 2013-2014, Isis Lovecruft
#             (c) 2007-2014, The Tor Project, Inc.
# :license: see LICENSE for licensing information

"""Classes for manipulating and storing Bridges and their attributes."""


import ipaddr
import logging
import os

from bridgedb.parse.addr import isValidIP
from bridgedb.parse.fingerprint import isValidFingerprint


class MalformedBridgeInfo(ValueError):
    """Raised when some information about a bridge appears malformed."""


class MalformedPluggableTransport(MalformedBridgeInfo):
    """Raised when information used to initialise a :class:`PluggableTransport`
    appears malformed.
    """

class InvalidPluggableTransportIP(MalformedBridgeInfo):
    """Raised when a :class:`PluggableTransport` has an invalid address."""


class ServerDescriptorDigestMismatch(MalformedBridgeInfo):
    """Raised when the digest in an ``@type bridge-networkstatus`` document
    doesn't match the hash digest of the ``@type bridge-server-descriptor``'s
    contents.
    """

class ServerDescriptorWithoutNetworkstatus(MalformedBridgeInfo):
    """Raised when we find a ``@type bridge-server-descriptor`` which was not
    mentioned in the latest ``@type bridge-networkstatus`` document.
    """

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

        if self.fast or self.guard or self.running or self.stable or self.valid:
            logging.debug("Parsed Flags: %s" % ' '.join(flags))


class PluggableTransport(object):
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
        self.fingerprint = fingerprint
        self.address = address
        self.port = port
        self.methodname = methodname
        self.arguments = arguments

        # Because we can intitialise this class with the __init__()
        # parameters, or use the ``updateFromStemTransport()`` method, we'll
        # only use the ``_runChecks()`` method now if we were initialised with
        # parameters:
        if (self.fingerprint or self.address or self.port or
            self.methodname or self.arguments):
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

          1. The :data:`fingerprint` is valid, according to
             :func:`~bridgedb.parse.fingerprint.isValidFingerprint`.

          2. The :data:`address` is valid, according to
             :func:`~bridgedb.parse.addr.isValidIP`.

          3. The :data:`port` is an integer, and that it is between the values
              of ``0`` and ``65535`` (inclusive).

          4. The :data:`arguments` is a dictionary.

        :raises MalformedPluggableTransport: if any of the above checks fails.
        """
        if not isValidFingerprint(self.fingerprint):
            raise MalformedPluggableTransport(
                ("Cannot create PluggableTransport with bad Bridge "
                 "fingerprint: %r.") % self.fingerprint)

        valid = isValidIP(self.address)
        if not valid:
            raise InvalidPluggableTransportIP(
                ("Cannot create PluggableTransport with address '%s'. "
                 "type(address)=%s.") % (self.address, type(self.address)))
        self.address = ipaddr.IPAddress(self.address)

        try:
            # Coerce the port to be an integer:
            self.port = int(self.port)
        except TypeError:
            raise MalformedPluggableTransport(
                ("Cannot create PluggableTransport with port type: %s.")
                % type(self.port))
        else:
            if not (0 <= self.port <= 65535):
                raise MalformedPluggableTransport(
                    ("Cannot create PluggableTransport with out-of-range port:"
                     " %r.") % self.port)

        if not isinstance(self.arguments, dict):
            raise MalformedPluggableTransport(
                ("Cannot create PluggableTransport with arguments type: %s")
                % type(self.arguments))

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
        self.fingerprint = fingerprint
        self.methodname = methodname
        self.address = kitchenSink[0]
        self.port = kitchenSink[1]
        self.arguments = self._parseArgumentsIntoDict(kitchenSink[2])
        self._runChecks()


class Bridge(object):
    """A single bridge, and all the information we have for it.

    :type fingerprint: str or None
    :ivar fingerprint:

    :type nickname: str or None
    :ivar nickname:

    :ivar orPort: int or None
    :ivar orPort:

    :ivar socksPort: int
    :ivar socksPort:

    :type dirPort: int
    :ivar dirPort:

    :type orAddresses: list
    :ivar orAddresses:

    :type transports: list
    :ivar transports:

    :type flags: :class:`~bridgedb.bridges.Flags`
    :ivar flags:

    :type hibernating: bool
    :ivar hibernating:

    :type contact: str or None
    :ivar contact: The contact information for the this bridge's operator.

    :type platform: str or None
    :ivar platform: The ``platform`` line taken from the
        ``@type bridge-server-descriptor``, e.g.
        ``'Tor 0.2.5.4-alpha on Linux'``.

    :type family: set or None
    :ivar family: The fingerprints of other bridges related to this one.
    """
    #: (bool) If ``True``, check that the signature of the bridge's
    #: ``@type bridge-server-descriptor`` is valid and that the signature was
    #: created with the ``signing-key`` contained in that descriptor.
    _checkServerDescriptorSignature = True

    def __init__(self):
        """Create a new ``Bridge``."""
        self.fingerprint = None
        self.nickname = None
        self.address = None
        self.orPort = None
        self.socksPort = 0  # Bridges should always have ``SOCKSPort`` and
        self.dirPort = 0    # ``DirPort`` set to ``0``
        self.orAddresses = []
        self.transports = []
        self.flags = Flags()
        self.hibernating = False

        self.bandwidth = None
        self.bandwidthAverage = None
        self.bandwidthBurst = None
        self.bandwidthObserverd = None

        self.contact = None
        self.family = None
        self.platform = None
        self.software = None
        self.os = None
        self.uptime = None

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

    def _updateORAddresses(self, orAddresses):
        for (address, port, ipVersion) in orAddresses:
            if not ipVersion:  # `False` means IPv4; `True` means IPv6.
                # See https://bugs.torproject.org/9380#comment:27
                warnings.warn(FutureWarning(
                    ("Got IPv4 address in 'a'/'or-address' line! "
                     "Desriptor format may have changed!")))
            self.orAddresses.append(tuple([address, port]))

    def assertOK(self):
        """Perform some additional validation on this bridge's info.

        We require that:

          1. This bridge's :data:`fingerprint` is valid, accoring to
             :func:`~bridgedb.parse.fingerprint.isValidFingerprint`.

          2. This bridge's :data:`address` and any IP addresses contained in
             :data:`orAddresses` are valid, according to
             :func:`~bridgedb.parse.addr.isValidIP`.

          3. The :data:`orPort` and any ports in :data:`orAddresses` are
             between ``1`` and ``65535`` (inclusive).

        :raises MalformedBridgeInfo: if something was found to be malformed or
            invalid.
        """
        malformed = []

        if not isValidFingerprint(self.fingerprint):
            malformed.append("Invalid fingerprint: '%s'" % self.fingerprint)
        if not isValidIP(self.address):
            malformed.append("Invalid ORPort address: '%s'" % self.address)
        if not (1 <= self.orPort <= 65535):
            malformed.append("Invalid ORPort port: '%d'" % self.orPort)
        for (address, port) in self.orAddresses:
            if not isValidIP(address):
                malformed.append("Invalid ORAddress address: '%s'" % address)
            if not (1 <= port <= 65535):
                malformed.append("Invalid ORAddress port: '%d'" % port)

        if malformed:
            raise MalformedBridgeInfo('\n'.join(malformed))

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

    def updateFromNetworkstatus(self, descriptor):
        """Update this bridge's attributes from a parsed networkstatus
        descriptor.

        :type ns: :api:`stem.descriptors.router_status_entry.RouterStatusEntry`
        :param ns:
        """
        self.descriptors['networkstatus'] = descriptor

        # These fields are *only* found in the networkstatus document:
        self.descriptorDigest = descriptor.digest
        self.flags.update(descriptor.flags)
        self.bandwidth = descriptor.bandwith

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
        :param descriptor:
        """
        self.descriptors['server'] = descriptor

        try:
            self._checkServerDescriptor(descriptor)
        except ValueError as error:
            logging.warn(error)
            # XXX should we throw away this descriptor?

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
        self.bandwidthObserved = descriptor.bandwidth_observed

        self.contact = descriptor.contact
        self.family = descriptor.family
        self.platform = descriptor.platform
        self.software = descriptor.tor_version
        self.os = descriptor.operating_system
        self.uptime = descriptor.uptime

        self.extrainfoDigest = descriptor.extrainfoDigest

    def updateFromExtraInfoDescriptor(self, descriptor):
        """Update this bridge's information from an extrainfo descriptor.

        .. todo:: The ``transport`` attribute of Stem's
            ``BridgeExtraInfoDescriptor`` class is a dictionary that uses the
            Pluggable Transport's eype as the keys. Meaning that if a bridge
            were to offer four instances of ``obfs3``, only one of them would
            get to us through Stem. This might pose a problem someday.

        :type descriptor:
            :api:`stem.descriptor.extrainfo_descriptor.BridgeExtraInfoDescriptor`
        :param descriptor: DOCDOC
        """
        self.descriptors['extrainfo'] = descriptor
