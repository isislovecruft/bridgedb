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
