# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_parse_descriptors ; -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2014, The Tor Project, Inc.
#             (c) 2014, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

from __future__ import print_function

import datetime
import logging

from stem.descriptor import extrainfo_descriptor
from stem.descriptor import server_descriptor
from stem.descriptor import parse_file
from stem.descriptor.router_status_entry import _parse_file as _parseNSFile
from stem.descriptor.router_status_entry import RouterStatusEntryV3

from bridgedb import safelog


def parseNetworkStatusFile(filename, validate=True, skipAnnotations=True,
                           descriptorClass=RouterStatusEntryV3):
    """Parse a file which contains an ``@type bridge-networkstatus`` document.

    See `ticket #12254 <https://bugs.torproject.org/12254>`__ for why
    networkstatus-bridges documents don't look anything like the networkstatus
    v2 documents that they are purported to look like. They are missing all
    headers, and the entire footer including authority signatures.

    :param str filename: The location of the file containing bridge
        networkstatus descriptors.
    :param bool validate: Passed along to Stem's parsers. If ``True``, the
        descriptors will raise exceptions if they do not meet some definition
        of correctness.
    :param bool skipAnnotations: If ``True``, skip parsing everything before the
        first ``r`` line.
    :param descriptorClass: A class (probably from
        :api:`stem.descriptors.router_status_entry`) which Stem will parse
        each descriptor it reads from **filename** into.
    :raises ValueError: if the contents of a descriptor are malformed and
        **validate** is ``True``.
    :raises IOError: if the file at **filename** can't be read.
    :rtype: list
    :returns: A list of
        :api:`stem.descriptor.router_status_entry.RouterStatusEntryV#`s.
    """
    routers = []

    logging.info("Parsing networkstatus file: %s" % filename)
    with open(filename) as fh:
        position = fh.tell()
        if skipAnnotations:
            while not fh.readline().startswith('r '):
                position = fh.tell()
        logging.debug("Skipping %d bytes of networkstatus file." % position)
        fh.seek(position)
        document = _parseNSFile(fh, validate, entry_class=descriptorClass)
        routers.extend(list(document))
    logging.info("Closed networkstatus file: %s" % filename)

    return routers

def parseServerDescriptorsFile(filename, validate=True):
    """Parse a file which contains ``@type bridge-server-descriptor``s.

    .. note:: ``validate`` defaults to ``False`` because there appears to be a
        bug in Leekspin, the fake descriptor generator, where Stem thinks the
        fingerprint doesn't match the key…

    .. note:: We have to lie to Stem, pretending that these are ``@type
        server-descriptor``s, **not** ``@type bridge-server-descriptor``s.
        See ticket `#11257`_.

    .. _`#11257`: https://trac.torproject.org/projects/tor/ticket/11257

    :param str filename: The file to parse descriptors from.
    :param bool validate: Whether or not to validate descriptor
        contents. (default: ``False``)
    :rtype: list
    :returns: A list of
        :api:`stem.descriptor.server_descriptor.RelayDescriptor`s.
    """
    logging.info("Parsing server descriptors with Stem: %s" % filename)
    descriptorType = 'server-descriptor 1.0'
    document = parse_file(filename, descriptorType, validate=validate)
    routers = list(document)
    return routers

def deduplicate(descriptors):
    """Deduplicate some descriptors, returning only the newest for each router.

    .. note:: If two descriptors for the same router are discovered, AND both
        descriptors have the **same** published timestamp, then the router's
        fingerprint WILL BE LOGGED ON PURPOSE, because we assume that router
        to be malicious (deliberately, or unintentionally).

    :param list descriptors: A list of
        :api:`stem.descriptor.server_descriptor.RelayDescriptor`s,
        :api:`stem.descriptor.extrainfo_descriptor.BridgeExtraInfoDescriptor`s,
        :api:`stem.descriptor.router_status_entry.RouterStatusEntryV2`s.
    """
    duplicates = {}
    nonDuplicates = {}

    for descriptor in descriptors:
        fingerprint = descriptor.fingerprint

        logging.debug("Deduplicating %s descriptor for router %s"
                      % (str(descriptor.__class__).rsplit('.', 1)[1],
                         safelog.logSafely(fingerprint)))

        if fingerprint in nonDuplicates.keys():
            # We already found a descriptor for this fingerprint:
            conflict = nonDuplicates[fingerprint]

            # If the descriptor we are currently parsing is newer than the
            # last one we found:
            if descriptor.published > conflict.published:
                # And if this is the first duplicate we've found for this
                # router, then create a list in the ``duplicates`` dictionary
                # for the router:
                if not fingerprint in duplicates.keys():
                    duplicates[fingerprint] = list()
                # Add this to the list of duplicates for this router:
                duplicates[fingerprint].append(conflict)
                # Finally, put the newest descriptor in the ``nonDuplicates``
                # dictionary:
                nonDuplicates[fingerprint] = descriptor
            # Same thing, but this time the one we're parsing is older:
            elif descriptor.published < conflict.published:
                if not fingerprint in duplicates.keys():
                    duplicates[fingerprint] = list()
                duplicates[fingerprint].append(descriptor)
            # This *shouldn't* happen. It would mean that two descriptors for
            # the same router had the same timestamps, probably meaning there
            # is a severely-messed up OR implementation out there. Let's log
            # its fingerprint (no matter what!) so that we can look up its
            # ``platform`` line in its server-descriptor and tell whoever
            # wrote that code that they're probably (D)DOSing the Tor network.
            else:
                logging.warn(("Duplicate descriptor with identical timestamp "
                              "(%s) for router with fingerprint '%s'!")
                             % (descriptor.published, fingerprint))

        # Hoorah! No duplicates! (yet...)
        else:
            nonDuplicates[fingerprint] = descriptor

    logging.info("Descriptor deduplication finished.")
    logging.info("Number of duplicates: %d" % len(duplicates))
    for (fingerprint, dittos) in duplicates.items():
        logging.info("  For %s: %d duplicates"
                     % (safelog.logSafely(fingerprint), len(dittos)))
    logging.info("Number of non-duplicates: %d" % len(nonDuplicates))

    return nonDuplicates

def parseBridgeExtraInfoFiles(*filenames, **kwargs):
    """Parse files which contain ``@type bridge-extrainfo-descriptor``s.

    .. note:: This function will call :func:`deduplicate` to deduplicate the
        extrainfo descriptors parsed from all **filenames**.

    :kwargs validate: If there is a ``'validate'`` keyword argument, its value
        will be passed along as the ``'validate'`` argument to
        :api:`stem.descriptor.extrainfo_descriptor.BridgeExtraInfoDescriptor`.
    :rtype: dict
    :returns: A dictionary mapping bridge fingerprints to deduplicated
        :api:`stem.descriptor.extrainfo_descriptor.BridgeExtraInfoDescriptor`s.
    """
    descriptors = []
    descriptorType = 'bridge-extra-info 1.1'

    validate = False
    if ('validate' in kwargs) and (kwargs['validate'] is True):
        validate = True

    for filename in filenames:
        logging.info("Parsing %s descriptors with Stem: %s"
                     % (descriptorType, filename))
        document = parse_file(filename, descriptorType, validate=validate)
        descriptors.extend([router for router in document])

    routers = deduplicate(descriptors)
    return routers
