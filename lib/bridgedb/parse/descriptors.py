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
from stem.descriptor import networkstatus
from stem.descriptor import server_descriptor
from stem.descriptor import parse_file

from bridgedb import safelog


def parseNetworkStatusFile(filename, validate=True):
    """Parse a file which contains an ``@type bridge-networkstatus`` document.

    :rtype: dict
    :returns: A dictionary of
        :api:`stem.descriptor.router_status_entry.RouterStatusEntryV2`.
    """
    logging.info("Parsing networkstatus entries with Stem: %s" % filename)

    fh = open(filename)
    descriptors = fh.read()
    fh.close()

    # See ticket #12254 for why networkstatus-bridges documents don't look
    # anything like the networkstatus v2 documents that they are purported to
    # look like. They are missing all headers, and the entire footer including
    # authority signatures.
    #
    # https://trac.torproject.org/projects/tor/ticket/12254
    #
    # As such, they do not currently start with a "published" line with an
    # ISO8601 timestamp, as stem expects them to:
    #
    if not descriptors.startswith("published"):
        precise = datetime.datetime.now().isoformat(sep=chr(0x20))
        timestamp = precise.rsplit('.', 1)[0]
        descriptors = "published {t}\n{d}".format(t=timestamp, d=descriptors)
    else:
        logging.warn(
            ("Networkstatus file '%s' started with 'published' line! Please "
             "revise this function!") % filename)

    routers = networkstatus.BridgeNetworkStatusDocument(descriptors,
                                                        validate=validate)
    return routers

def parseServerDescriptorsFile(filename, validate=False):
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

    routers = [router for router in document]
    return routers

def deduplicate(descriptors):
    duplicates = []
    nonDuplicates = []

    for descriptor in descriptors:
        router = descriptors.pop(descriptors.index(descriptor))
        fingerprint = router.fingerprint

        logging.debug("Deduplicating %s descriptor for router %s"
                      % (str(router.__class__).rsplit('.', 1)[1],
                         safelog.logSafely(fingerprint)))

        for possibleDuplicate in descriptors:
            if fingerprint == possibleDuplicate.fingerprint:
                logging.warn("Duplicate extra-info descriptor for router %s"
                             % safelog.logSafely(fingerprint))
                if router.published > possibleDuplicate.published:
                    # The router is newer than the duplicate, so get rid of
                    # the duplicate:
                    duplicates.append(possibleDuplicate)
                elif router.published < possibleDuplicate.published:
                    # The router is older than the duplicate, so replace our
                    # router:
                    duplicates.append(router)
                    router = possibleDuplicate
                else:
                    duplicates.append(possibleDuplicate)
                    logging.warn(("Duplicate descriptor and original "
                                  "descriptor for router %s both had the same "
                                  "timestamp: %s")
                                 % (safelog.logSafely(fingerprint),
                                    router.published))
            else:
                nonDuplicates.append(router)

    logging.info("Descriptor deduplication finished.")
    logging.info("Number of duplicates: %d" % len(duplicates))
    logging.info("Number of non-duplicates: %d" % len(nonDuplicates))
    return nonDuplicates


def parseBridgeExtraInfoFiles(*filenames, **kwargs):
    """Parse files which contain ``@type bridge-extrainfo-descriptor``s.

    :kwargs: If there is a ``'validate'`` keyword argument, its value will be
        passed along as the ``'validate'`` argument to
        :api:`stem.descriptor.extrainfo_descriptor.BridgeExtraInfoDescriptor`.
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
