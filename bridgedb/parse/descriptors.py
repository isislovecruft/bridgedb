# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_parse_descriptors ; -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2015, The Tor Project, Inc.
#             (c) 2014-2015, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""Parsers for Tor Bridge descriptors, including ``bridge-networkstatus``
documents, ``bridge-server-descriptor``s, and ``bridge-extrainfo``
descriptors.

.. py:module:: bridgedb.parse.descriptors
    :synopsis: Parsers for Tor Bridge descriptors.

bridgedb.parse.descriptors
===========================
::

 DescriptorWarning - Raised when we parse a very odd descriptor.
 deduplicate - Deduplicate a container of descriptors, keeping only the newest
               descriptor for each router.
 parseNetworkStatusFile - Parse a bridge-networkstatus document generated and
                          given to us by the BridgeAuthority.
 parseServerDescriptorsFile - Parse a file containing
                              bridge-server-descriptors.
 parseExtraInfoFiles - Parse (multiple) file(s) containing bridge-extrainfo
                       descriptors.
..
"""

from __future__ import print_function

import datetime
import logging
import os
import shutil

from stem import ProtocolError
from stem.descriptor import parse_file
from stem.descriptor.router_status_entry import _parse_file as _parseNSFile
from stem.descriptor.router_status_entry import RouterStatusEntryV3

from bridgedb import safelog
from bridgedb.parse.nickname import InvalidRouterNickname


class DescriptorWarning(Warning):
    """Raised when we parse a very odd descriptor."""


def _copyUnparseableDescriptorFile(filename):
    """Save a copy of the bad descriptor file for later debugging.

    If the old filename was ``'descriptors/cached-extrainfo.new'``, then the
    name of the copy will be something like
    ``'descriptors/2014-11-05-01:57:23_cached-extrainfo.new.unparseable'``.

    :param str filename: The path to the unparseable descriptor file that we
        should save a copy of.
    :rtype: bool
    :returns: ``True`` if a copy of the file was saved successfully, and
        ``False`` otherwise.
    """
    timestamp = datetime.datetime.now()
    timestamp = timestamp.isoformat(sep=chr(0x2d))
    timestamp = timestamp.rsplit('.', 1)[0]

    path, sep, fname = filename.rpartition(os.path.sep)
    newfilename = "%s%s%s_%s%sunparseable" % (path, sep, timestamp,
                                              fname, os.path.extsep)

    logging.info(("Unparseable descriptor file '%s' will be copied to '%s' "
                  "for debugging.") % (filename, newfilename))

    try:
        shutil.copyfile(filename, newfilename)
    except Exception as error:  # pragma: no cover
        logging.error(("Could not save copy of unparseable descriptor file "
                       "in '%s': %s") % (newfilename, str(error)))
        return False
    else:
        logging.debug(("Successfully finished saving a copy of an unparseable "
                       "descriptor file."))
        return True

def parseNetworkStatusFile(filename, validate=True, skipAnnotations=True,
                           descriptorClass=RouterStatusEntryV3):
    """Parse a file which contains an ``@type bridge-networkstatus`` document.

    See :trac:`12254` for why networkstatus-bridges documents don't look
    anything like the networkstatus v2 documents that they are purported to
    look like. They are missing all headers, and the entire footer (including
    authority signatures).

    :param str filename: The location of the file containing bridge
        networkstatus descriptors.
    :param bool validate: Passed along to Stem's parsers. If ``True``, the
        descriptors will raise exceptions if they do not meet some definition
        of correctness.
    :param bool skipAnnotations: If ``True``, skip parsing everything before the
        first ``r`` line.
    :param descriptorClass: A class (probably from
        :mod:`stem.descriptors.router_status_entry`, i.e.
        :class:`stem.descriptor.router_status_entry.RouterStatusEntryV2` or
        :class:`stem.descriptor.router_status_entry.RouterStatusEntryV3`)
        which Stem will parse each descriptor it reads from **filename** into.
    :raises InvalidRouterNickname: if one of the routers in the networkstatus
        file had a nickname which does not conform to Tor's nickname
        specification.
    :raises ValueError: if the contents of a descriptor are malformed and
        **validate** is ``True``.
    :raises IOError: if the file at **filename** can't be read.
    :rtype: list
    :returns: A list of
        :class:`stem.descriptor.router_status_entry.RouterStatusEntry`.
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

        try:
            routers.extend(list(document))
        except ValueError as error:
            if "nickname isn't valid" in str(error):
                raise InvalidRouterNickname(str(error))
            else:
                raise ValueError(str(error))

    logging.info("Closed networkstatus file: %s" % filename)

    return routers

def parseServerDescriptorsFile(filename, validate=True):
    """Open and parse **filename**, which should contain
    ``@type bridge-server-descriptor``.

    .. note:: We have to lie to Stem, pretending that these are
        ``@type server-descriptor``, **not**
        ``@type bridge-server-descriptor``. See :trac:`11257`.

    :param str filename: The file to parse descriptors from.
    :param bool validate: Whether or not to validate descriptor
        contents. (default: ``True``)
    :rtype: list
    :returns: A list of
        :class:`stem.descriptor.server_descriptor.RelayDescriptor`s.
    """
    logging.info("Parsing server descriptors with Stem: %s" % filename)
    descriptorType = 'server-descriptor 1.0'
    document = parse_file(filename, descriptorType, validate=validate)
    routers = list(document)
    return routers

def __cmp_published__(x, y):
    """A custom ``cmp()`` which sorts descriptors by published date.

    :rtype: int
    :returns: Return negative if x<y, zero if x==y, positive if x>y.
    """
    if x.published < y.published:
        return -1
    elif x.published == y.published:
        # This *shouldn't* happen. It would mean that two descriptors for
        # the same router had the same timestamps, probably meaning there
        # is a severely-messed up OR implementation out there. Let's log
        # its fingerprint (no matter what!) so that we can look up its
        # ``platform`` line in its server-descriptor and tell whoever
        # wrote that code that they're probably (D)DOSing the Tor network.
        logging.warn(("Duplicate descriptor with identical timestamp (%s) "
                      "for bridge %s with fingerprint %s !") %
                     (x.published, x.nickname, x.fingerprint))
        return 0
    elif x.published > y.published:
        return 1

def deduplicate(descriptors, statistics=False):
    """Deduplicate some descriptors, returning only the newest for each router.

    .. note:: If two descriptors for the same router are discovered, AND both
        descriptors have the **same** published timestamp, then the router's
        fingerprint WILL BE LOGGED ON PURPOSE, because we assume that router
        to be broken or malicious.

    :param list descriptors: A list of
        :class:`stem.descriptor.server_descriptor.RelayDescriptor`,
        :class:`stem.descriptor.extrainfo_descriptor.BridgeExtraInfoDescriptor`,
        or :class:`stem.descriptor.router_status_entry.RouterStatusEntry`.
    :param bool statistics: If ``True``, log some extra statistics about the
        number of duplicates.
    :rtype: dict
    :returns: A dictionary mapping router fingerprints to their newest
        available descriptor.
    """
    duplicates = {}
    newest = {}

    for descriptor in descriptors:
        fingerprint = descriptor.fingerprint
        if fingerprint in duplicates:
            duplicates[fingerprint].append(descriptor)
        else:
            duplicates[fingerprint] = [descriptor,]

    for fingerprint, dupes in duplicates.items():
        dupes.sort(cmp=__cmp_published__)
        first = dupes.pop()
        newest[fingerprint] = first
        duplicates[fingerprint] = dupes

    if statistics:
        # sorted() won't sort by values (or anything that isn't the first item
        # in its container), period, no matter what the cmp function is.
        totals  = sorted([(len(v), k,) for k, v in duplicates.viewitems()])
        total   = sum([k for (k, v) in totals])
        bridges = len(duplicates)
        top     = 10 if bridges >= 10 else bridges
        logging.info("Number of bridges with duplicates: %5d" % bridges)
        logging.info("Total duplicate descriptors:       %5d" % total)
        logging.info("Bridges with the most duplicates (Top %d):" % top)
        for i, (subtotal, bridge) in zip(range(1, top + 1), totals[:top]):
            logging.info("  #%d %s: %d duplicates" % (i, bridge, subtotal))

    logging.info("Descriptor deduplication finished.")

    return newest

def parseExtraInfoFiles(*filenames, **kwargs):
    """Open **filenames** and parse any ``@type bridge-extrainfo-descriptor``
    contained within.

    .. warning:: This function will *not* check that the ``router-signature``
        at the end of the extrainfo descriptor is valid. See
        ``bridgedb.bridges.Bridge._verifyExtraInfoSignature`` for a method for
        checking the signature.  The signature cannot be checked here, because
        to do so, we would need the latest, valid, corresponding
        ``signing-key`` for the Bridge.

    .. note:: This function will call :func:`deduplicate` to deduplicate the
        extrainfo descriptors parsed from all **filenames**.

    :kwargs validate: If there is a ``'validate'`` keyword argument, its value
        will be passed along as the ``'validate'`` argument to
        :class:`stem.descriptor.extrainfo_descriptor.BridgeExtraInfoDescriptor`.
        The ``'validate'`` keyword argument defaults to ``True``, meaning that
        the hash digest stored in the ``router-digest`` line will be checked
        against the actual contents of the descriptor and the extrainfo
        document's signature will be verified.
    :rtype: dict
    :returns: A dictionary mapping bridge fingerprints to their corresponding,
        deduplicated
        :class:`stem.descriptor.extrainfo_descriptor.RelayExtraInfoDescriptor`.
    """
    descriptors = []

    # The ``stem.descriptor.extrainfo_descriptor.BridgeExtraInfoDescriptor``
    # class (with ``descriptorType = 'bridge-extra-info 1.1``) is unsuitable
    # for our purposes for the following reasons:
    #
    #   1. It expects a ``router-digest`` line, which is only present in
    #      sanitised bridge extrainfo descriptors.
    #
    #   2. It doesn't check the ``router-signature`` (nor does it expect there
    #      to be a signature).
    descriptorType = 'extra-info 1.0'

    validate = True
    if ('validate' in kwargs) and (kwargs['validate'] is False):
        validate = False

    for filename in filenames:
        logging.info("Parsing %s descriptors in %s..."
                     % (descriptorType, filename))

        document = parse_file(filename, descriptorType, validate=validate)

        try:
            for router in document:
                descriptors.append(router)
        except (ValueError, ProtocolError) as error:
            logging.error(
                ("Stem exception while parsing extrainfo descriptor from "
                 "file '%s':\n%s") % (filename, str(error)))
            _copyUnparseableDescriptorFile(filename)

    routers = deduplicate(descriptors)
    return routers
