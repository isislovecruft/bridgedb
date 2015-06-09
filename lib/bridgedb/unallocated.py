# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_unallocated ; -*-
# ____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2013-2015, Isis Lovecruft
#             (c) 2007-2015, The Tor Project, Inc.
# :license: see LICENSE for licensing information
# ____________________________________________________________________________


"""Functionality for managing unallocated :class:`~bridgedb.bridges.Bridge`s.
"""

import logging
import time

from twisted.internet import reactor

import bridgedb.Storage

from bridgedb.bridges import IBridge
from bridgedb.bridges import Bridge
from bridgedb.crypto import getHMAC
from bridgedb.distribute import Distributor
from bridgedb.hashring import Hashring


#: Prefix for bucket names in the database so we can distinguish them from real
#: distributors.
BUCKET_PREFIX = "pseudo_"


def sortAndExport(filename, lines, mode='w'):
    """Sort the **lines** and export them to **filename**.

    :param str filename: The path name of the file to the **lines** to.
    :param list lines: An iterable of lines to write to **filename**.
    :param str mode: The mode to open **filename** with.
    """
    lines.sort()
    with open(filename, mode) as fh:
        [fh.write(line) for line in lines]


class UnallocatedDistributor(Distributor):
    """A :class:`~bridgedb.distribute.Distributor` which doesn't actually
    distribute its :class:`~bridgedb.bridges.Bridge`s, but instead saves them
    for a day when the internet-censorship nazis decide to rain on everyone's
    parade.
    """
    def __init__(self, key):
        """Create a new :class:`Distributor` for storing otherwise unallocated
        :class:`~bridgedb.bridges.Bridge`s.

        :param str key: A master key for this Distributor. This is used to HMAC
            bridge and client data in order to arrange them into hashring
            structures.
        """
        super(UnallocatedDistributor, self).__init__(key)
        self.hashring = Hashring(getHMAC(key, "Assign-Bridges-To-Hashring"))
        self.hashring.exportToFile = self.exportToFile
        self.name = "unallocated"

    @property
    def fingerprints(self):
        """The fingerprints of all the :class:`~bridgedb.bridges.Bridge`s for
        this distributor.
        """
        fingerprints = self.hashring._keyToName.values()
        for subring in self.hashring.subrings:
            fingerprints.extend(subring._keyToName.values())
        return fingerprints

    def addChannel(self, channel, bridges=None):
        """Add a new out-of-band distribution **channel** for some unallocated
        **bridges**.

        :param str channel: A name for the out-of-band distribution channel.
        :type bridges: list or ``None``
        :param bridges: A list of implementers of
            :class:`~bridgedb.bridges.IBridge`, or
            :class:`bridgedb.Storage.BridgeData` (or both types).  If given,
            these will be imported into the new :class:`Hashring`.
        """
        converted = []

        if bridges:
            for bridge in bridges:
                if isinstance(bridge, bridgedb.Storage.BridgeData):
                    brdg = Bridge()
                    brdg.fingerprint = bridge.hex_key
                    brdg.address = bridge.address
                    brdg.orPort = bridge.or_port
                    converted.append(brdg)
                elif IBridge.providedBy(bridge):
                    converted.append(bridge)

        self.hashring.addSubring(Hashring(self.hashring.key), channel,
                                 importFrom=converted)

    def exportToFile(self, filename=None, description="", mode='w'):
        """Export all of this distributor's bridges to **filename**, with an
        optional **description**.

        :type filename: str or ``None``
        :param filename: The name of the file to write to.
        :param str description: A description to add to the line for each
            exported bridge. The distribution channel (a.k.a. "bucket") for
            each bridge is automatically included in the description.
        :param chr mode: The mode to open the file with.
        """
        with bridgedb.Storage.getDB() as db:
            unallocated = db.getUnallocated(BUCKET_PREFIX)

        date = time.strftime("%Y-%m-%d")

        for channel, bridges in unallocated.items():
            lines = []
            describe = description + " channel=%s" % channel
            subrings = [subring.name for subring in self.hashring.subrings]

            if channel not in subrings:
                self.addChannel(channel, bridges)

            for bridge in bridges:
                if bridge.hex_key not in self.fingerprints:
                    continue
                lines.append("%s %s:%s %s\n" % (bridge.hex_key, bridge.address,
                                                bridge.or_port, describe))

            if not filename:
                filename = ''.join([channel, '-', date, '.brdgs'])

            logging.info("Exporting bridges to file: %s" % filename)
            reactor.callInThread(sortAndExport, filename, lines, mode)
